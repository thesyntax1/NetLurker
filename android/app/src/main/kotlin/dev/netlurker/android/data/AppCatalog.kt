package dev.netlurker.android.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import dev.netlurker.android.core.AppTraffic
import java.io.File
import java.security.MessageDigest

/** Installed package metadata and APK signing certificates read through PackageManager. */
class AppCatalog(private val context: Context) {

    private val pm: PackageManager = context.packageManager
    private val hashCache = HashMap<String, String>()

    data class AppRecord(
        val uid: Int,
        val packageName: String,
        val label: String,
        val system: Boolean,
        val versionName: String?,
        val apkPath: String?,
        val installer: String?,
        val firstInstallMs: Long,
        val lastUpdateMs: Long,
        val targetSdk: Int,
        val requestedPermissions: List<String>,
        val signerSubject: String?,
        val signerIssuer: String?,
        val signerSha256: String?
    )

    fun load(): List<AppRecord> {
        val applications: List<ApplicationInfo> = runCatching {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }.getOrDefault(emptyList())

        val out = ArrayList<AppRecord>(applications.size)
        for (info in applications) {
            val packageName = info.packageName
            val packageInfo: PackageInfo? = runCatching {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            }.getOrNull()

            val signing = signingCertificate(packageName)
            out += AppRecord(
                uid = info.uid,
                packageName = packageName,
                label = runCatching { pm.getApplicationLabel(info).toString() }
                    .getOrDefault(packageName),
                system = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
                versionName = packageInfo?.versionName,
                apkPath = info.sourceDir,
                installer = installerOf(packageName),
                firstInstallMs = packageInfo?.firstInstallTime ?: 0L,
                lastUpdateMs = packageInfo?.lastUpdateTime ?: 0L,
                targetSdk = info.targetSdkVersion,
                requestedPermissions = packageInfo?.requestedPermissions?.toList() ?: emptyList(),
                signerSubject = signing?.first,
                signerIssuer = signing?.second,
                signerSha256 = signing?.third
            )
        }
        return out.sortedWith(
            compareBy<AppRecord> { it.system }.thenBy { it.label.lowercase() }
        )
    }

    /** @return subject DN, issuer DN, SHA-256 of the certificate — or null if unreadable. */
    private fun signingCertificate(packageName: String): Triple<String, String, String>? {
        val certificates = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signingInfo = info.signingInfo
                    ?: return@runCatching emptyArray<android.content.pm.Signature>()
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures
            }
        }.getOrNull() ?: return null

        val certificate = certificates?.firstOrNull() ?: return null
        return runCatching {
            val x509 = certificate as java.security.cert.X509Certificate
            Triple(
                x509.subjectX500Principal.name,
                x509.issuerX500Principal.name,
                sha256Hex(certificate.toByteArray())
            )
        }.getOrNull()
    }

    private fun installerOf(packageName: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    }.getOrNull()

    /**
     * SHA-256 of the installed APK. Computed on demand and cached: hashing every package at
     * startup would cost seconds and battery for a value most rows never display.
     */
    fun apkSha256(path: String?): String? {
        if (path.isNullOrBlank()) return null
        hashCache[path]?.let { return it }
        val file = File(path)
        if (!file.exists() || !file.canRead()) return null
        val digest = runCatching {
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    md.update(buffer, 0, read)
                }
            }
            sha256Hex(md.digest())
        }.getOrNull() ?: return null
        hashCache[path] = digest
        return digest
    }

    fun toTrafficRows(records: List<AppRecord>): List<AppTraffic> = records.map { record ->
        AppTraffic(
                supported = false,
            uid = record.uid,
            packageName = record.packageName,
            label = record.label,
            rxBytes = 0,
            txBytes = 0,
            system = record.system,
            versionName = record.versionName,
            installer = record.installer,
            apkPath = record.apkPath,
            signerSubject = record.signerSubject,
            signerIssuer = record.signerIssuer,
            signerSha256 = record.signerSha256,
            firstInstallMs = record.firstInstallMs,
            lastUpdateMs = record.lastUpdateMs,
            targetSdk = record.targetSdk,
            requestedPermissions = record.requestedPermissions
        )
    }

    private fun sha256Hex(bytes: ByteArray): String =
        bytes.joinToString("") { String.format(java.util.Locale.ROOT, "%02x", it) }
}
