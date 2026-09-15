package dev.netlurker.android

import android.app.Application
import android.content.Context
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.netlurker.android.core.AnomalyAlert
import dev.netlurker.android.core.AppTraffic
import dev.netlurker.android.core.CellularInfo
import dev.netlurker.android.core.DeviceSnapshot
import dev.netlurker.android.core.ExportSnapshot
import dev.netlurker.android.core.Format
import dev.netlurker.android.core.IntelStatus
import dev.netlurker.android.core.InterfaceInfo
import dev.netlurker.android.core.LinkInfo
import dev.netlurker.android.core.Target
import dev.netlurker.android.core.WifiInfo
import dev.netlurker.android.data.AppCatalog
import dev.netlurker.android.data.IntelRepository
import dev.netlurker.android.data.HostsFile
import dev.netlurker.android.data.NetworkSource
import dev.netlurker.android.data.SessionHistory
import dev.netlurker.android.data.Settings
import dev.netlurker.android.data.TrafficSource
import dev.netlurker.android.intel.PublicIp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The single source of truth for the UI.
 *
 * One poll loop drives everything: read the counters, compute the deltas, feed the
 * baselines, publish. Rates are derived from real elapsed time between polls, so a device
 * that throttles the app in doze mode shows a lower sampling rate rather than invented
 * numbers.
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    val settings = Settings(application)
    val intel = IntelRepository(application, settings, viewModelScope)
    val history = SessionHistory()

    private val traffic = TrafficSource()
    private val catalog = AppCatalog(application)
    private val network = NetworkSource(application)
    private val notifier = Notifier(application)

    private val _apps = MutableStateFlow<List<AppTraffic>>(emptyList())
    val apps: StateFlow<List<AppTraffic>> = _apps.asStateFlow()

    private val _snapshot = MutableStateFlow<TrafficSource.Snapshot?>(null)
    val snapshot: StateFlow<TrafficSource.Snapshot?> = _snapshot.asStateFlow()

    private val _link = MutableStateFlow<LinkInfo?>(null)
    val link: StateFlow<LinkInfo?> = _link.asStateFlow()

    private val _wifi = MutableStateFlow<WifiInfo?>(null)
    val wifi: StateFlow<WifiInfo?> = _wifi.asStateFlow()

    private val _cellular = MutableStateFlow<CellularInfo?>(null)
    val cellular: StateFlow<CellularInfo?> = _cellular.asStateFlow()

    private val _interfaces = MutableStateFlow<List<InterfaceInfo>>(emptyList())
    val interfaces: StateFlow<List<InterfaceInfo>> = _interfaces.asStateFlow()

    private val _hosts = MutableStateFlow(HostsFile.Snapshot(readable = false, entries = 0))
    val hosts: StateFlow<HostsFile.Snapshot> = _hosts.asStateFlow()

    private val _device = MutableStateFlow<DeviceSnapshot?>(null)
    val device: StateFlow<DeviceSnapshot?> = _device.asStateFlow()

    private val _alerts = MutableStateFlow<List<AnomalyAlert>>(emptyList())
    val alerts: StateFlow<List<AnomalyAlert>> = _alerts.asStateFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _status = MutableStateFlow("")
    val status: StateFlow<String> = _status.asStateFlow()

    private val _catalogLoaded = MutableStateFlow(false)
    val catalogLoaded: StateFlow<Boolean> = _catalogLoaded.asStateFlow()

    private var pollJob: Job? = null
    private var networkJob: Job? = null
    private var lastPollAtMs = 0L
    private var locationGranted = false

    val trafficSupported: Boolean get() = traffic.supported

    init {
        history.restoreBaselines(
            readBaselineCache(application)
        )
        notifier.ensureChannel()
        loadDevice()
        loadCatalog()
    }

    // ------------------------------------------------------------------ lifecycle

    fun start() {
        if (_running.value) return
        _running.value = true
        refreshNetwork()
        pollJob = viewModelScope.launch(Dispatchers.Default) {
            while (isActive) {
                poll()
                delay(settings.refreshMs)
            }
        }
    }

    fun stop() {
        _running.value = false
        pollJob?.cancel()
        pollJob = null
        persist()
    }

    fun setLocationPermission(granted: Boolean) {
        if (locationGranted != granted) {
            locationGranted = granted
            refreshNetwork()
        }
    }

    fun setNotificationsEnabled(enabled: Boolean) {
        settings.anomalyNotifications = enabled
    }

    /** Re-reads everything that is not on the poll loop. */
    fun refreshNetwork() {
        networkJob?.cancel()
        networkJob = viewModelScope.launch(Dispatchers.IO) {
            _link.value = runCatching { network.activeLink() }.getOrNull()
            _wifi.value = runCatching { network.wifi(locationGranted) }.getOrNull()
            _cellular.value = runCatching { network.cellular() }.getOrNull()
            _interfaces.value = runCatching { network.interfaces() }.getOrDefault(emptyList())
            _hosts.value = HostsFile.read()
            if (settings.publicIpEnabled) {
                _device.value = _device.value?.copy(publicIpStatus = IntelStatus.PENDING)
                val (ip, error) = PublicIp.lookup()
                _device.value = _device.value?.copy(
                    publicIp = ip,
                    publicIpStatus = if (ip != null) IntelStatus.OK else IntelStatus.FAILED,
                    publicIpDetail = error
                )
            } else if (_device.value?.publicIpStatus == IntelStatus.PENDING) {
                _device.value = _device.value?.copy(publicIpStatus = IntelStatus.DISABLED)
            }
        }
    }

    fun resetSession() {
        traffic.resetSession()
        history.reset()
        _alerts.value = emptyList()
        poll()
    }

    // ----------------------------------------------------------------------- poll

    private fun poll() {
        val now = System.currentTimeMillis()
        val interval = if (lastPollAtMs == 0L) 0L else now - lastPollAtMs
        lastPollAtMs = now

        val current = runCatching { traffic.snapshot() }.getOrNull() ?: return
        _snapshot.value = current

        val previous = _apps.value
        if (previous.isNotEmpty()) {
            val rated = traffic.applyRates(previous, now)
            _apps.value = rated

            val perApp = HashMap<String, Long>(rated.size)
            for (app in rated) {
                if (app.totalBytes > 0) perApp[app.label] = app.totalBytes
            }
            val fresh = history.record(
                totalInBytes = current.totalRxBytes,
                totalOutBytes = current.totalTxBytes,
                perApp = perApp,
                intervalMs = interval
            )
            if (fresh.isNotEmpty()) {
                _alerts.value = history.alertsSnapshot
                if (settings.anomalyNotifications && notifier.canNotify(getApplication())) {
                    for (alert in fresh) notifier.anomaly(alert)
                }
            }
        }
    }

    // -------------------------------------------------------------------- loading

    private fun loadCatalog() {
        viewModelScope.launch(Dispatchers.IO) {
            val records = runCatching { catalog.load() }.getOrDefault(emptyList())
            val rows = catalog.toTrafficRows(records)
            _apps.value = rows
            _catalogLoaded.value = true
            _status.value = if (rows.isEmpty()) "no applications visible" else "${rows.size} applications"
        }
    }

    private fun loadDevice() {
        _device.value = DeviceSnapshot(
            model = Build.MODEL ?: "?",
            manufacturer = Build.MANUFACTURER ?: "?",
            androidRelease = Build.VERSION.RELEASE ?: "?",
            sdkInt = Build.VERSION.SDK_INT,
            securityPatch = Build.VERSION.SECURITY_PATCH ?: "?",
            uptimeMs = android.os.SystemClock.elapsedRealtime(),
            publicIpStatus = if (settings.publicIpEnabled) IntelStatus.IDLE else IntelStatus.DISABLED
        )
    }

    // --------------------------------------------------------------------- export

    /** APK hash is computed lazily; call this before exporting if the hash should be there. */
    suspend fun enrichApkHashes(limit: Int = 25) = withContext(Dispatchers.IO) {
        val rows = _apps.value.sortedByDescending { it.totalBytes }
        var changed = false
        for (app in rows.take(limit)) {
            if (app.apkSha256 != null || app.apkPath == null) continue
            val hash = catalog.apkSha256(app.apkPath) ?: continue
            _apps.value = _apps.value.map {
                if (it.uid == app.uid) it.copy(apkSha256 = hash) else it
            }
            changed = true
        }
        changed
    }

    /** Hashes one APK on the IO dispatcher when the user opens its detail panel. */
    /**
     * The application-level verdict. Recomputed on read: the inputs are small and callers
     * recompose around data they already observe.
     */
    fun appVerdict(app: AppTraffic): Verdict = RiskEngine.evaluateApp(
        app,
        _alerts.value.firstOrNull { it.subject == app.label },
        history.beaconPattern(app.label)
    )

    fun onApkHash(app: AppTraffic) {
        if (app.apkPath == null || app.apkSha256 != null) return
        viewModelScope.launch(Dispatchers.IO) {
            val hash = catalog.apkSha256(app.apkPath) ?: return@launch
            _apps.value = _apps.value.map {
                if (it.uid == app.uid) it.copy(apkSha256 = hash) else it
            }
        }
    }

    fun buildExportSnapshot(language: String, kpis: List<Pair<String, String>>): ExportSnapshot {
        val current = _snapshot.value
        return ExportSnapshot(
            generatedAtMs = System.currentTimeMillis(),
            appVersion = BuildConfig.VERSION_NAME,
            language = language,
            device = _device.value,
            link = _link.value,
            wifi = _wifi.value,
            cellular = _cellular.value,
            apps = _apps.value,
            targets = intel.targets.value,
            alerts = _alerts.value,
            kpis = kpis,
            trafficSupported = traffic.supported,
            elapsedMs = current?.let { history.elapsedMs } ?: 0L
        )
    }

    fun defaultKpis(): List<Pair<String, String>> {
        val current = _snapshot.value
        val apps = _apps.value
        return listOf(
            "download" to Format.bytesPerSec(current?.rateInBytesPerSec ?: 0.0),
            "upload" to Format.bytesPerSec(current?.rateOutBytesPerSec ?: 0.0),
            "session_down" to Format.bytes(current?.sessionRxBytes ?: 0L),
            "session_up" to Format.bytes(current?.sessionTxBytes ?: 0L),
            "apps" to apps.size.toString(),
            "active_apps" to apps.count { it.active }.toString(),
            "destinations" to intel.targets.value.size.toString(),
            "suspicious" to intel.targets.value.count { it.verdict.score >= 45 }.toString(),
            "anomalies" to _alerts.value.size.toString(),
            "uptime" to Format.durationShort((android.os.SystemClock.elapsedRealtime()) / 1000L)
        )
    }

    // ------------------------------------------------------------------ persistence

    fun persist() {
        intel.persistCaches()
        writeBaselineCache(getApplication(), history.serializeBaselines())
    }

    private fun readBaselineCache(context: Context): List<String> {
        val file = java.io.File(context.filesDir, "baseline.tsv")
        if (!file.exists()) return emptyList()
        return runCatching { file.readLines() }.getOrDefault(emptyList())
    }

    private fun writeBaselineCache(context: Context, lines: List<String>) {
        runCatching {
            java.io.File(context.filesDir, "baseline.tsv")
                .printWriter(Charsets.UTF_8).use { writer ->
                    for (line in lines) writer.println(line)
                }
        }
    }

    override fun onCleared() {
        persist()
        super.onCleared()
    }
}
