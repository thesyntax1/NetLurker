package dev.netlurker.android.intel

import dev.netlurker.android.core.GeoInfo
import dev.netlurker.android.core.Ip
import org.json.JSONArray
import org.json.JSONObject

/**
 * IP geolocation via ip-api.com, the same provider the desktop build uses, with the same
 * batch endpoint and the same field list so both platforms report identical values.
 *
 * Privacy note that is also true on the desktop: the free tier is plain HTTP, and the only
 * data leaving the device is the list of IP addresses being looked up.
 */
object GeoApi {

    private const val FIELDS = "status,message,country,countryCode,region,regionName,city," +
        "isp,org,as,asname,reverse,mobile,proxy,hosting,query"

    /** The free tier allows 100 addresses per batch and 45 requests per minute. */
    const val MAX_BATCH = 100

    class GeoFailure(message: String, val offline: Boolean) : Exception(message)

    /** @return map of query address to parsed info. */
    fun batch(ips: List<String>, timeoutMs: Int = 8_000): Map<String, GeoInfo> {
        if (ips.isEmpty()) return emptyMap()
        val payload = JSONArray().apply { ips.forEach { put(it) } }.toString()
        val response = Http.post(
            url = "http://ip-api.com/batch?fields=$FIELDS",
            body = payload,
            contentType = "application/json",
            timeoutMs = timeoutMs
        )
        if (!response.ok) {
            throw GeoFailure(response.error ?: "request failed", response.offline)
        }
        val array = runCatching { JSONArray(response.body) }
            .getOrElse { throw GeoFailure("unparsable response: ${it.message}", false) }

        val out = LinkedHashMap<String, GeoInfo>()
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            val query = obj.optString("query")
            if (query.isBlank()) continue
            if (obj.optString("status") != "success") {
                // A "fail" answer is still an answer: the address has no record. Callers
                // record it as not-found rather than retrying forever.
                out[query] = GeoInfo()
                continue
            }
            out[query] = GeoInfo(
                country = obj.optString("country"),
                countryCode = obj.optString("countryCode"),
                city = obj.optString("city"),
                region = obj.optString("regionName"),
                isp = obj.optString("isp"),
                org = obj.optString("org").ifBlank { obj.optString("isp") },
                asn = obj.optString("as"),
                asname = obj.optString("asname"),
                host = obj.optString("reverse"),
                mobile = obj.optBoolean("mobile"),
                proxy = obj.optBoolean("proxy"),
                hosting = obj.optBoolean("hosting")
            )
        }
        return out
    }

    fun single(ip: String, timeoutMs: Int = 8_000): GeoInfo? =
        batch(listOf(ip), timeoutMs).entries.firstOrNull {
            it.key == ip || Ip.sameAddress(it.key, ip)
        }?.value
}

/** Public egress address. Only queried when the user turns it on. */
object PublicIp {

    private val endpoints = listOf(
        "https://api.ipify.org?format=json",
        "https://api64.ipify.org?format=json"
    )

    fun lookup(timeoutMs: Int = 8_000): Pair<String?, String?> {
        for (endpoint in endpoints) {
            val response = Http.get(endpoint, timeoutMs = timeoutMs)
            if (!response.ok) continue
            val ip = runCatching { JSONObject(response.body).optString("ip") }.getOrNull()
            if (!ip.isNullOrBlank() && Ip.isIp(ip)) return ip to null
        }
        return null to "no provider answered"
    }
}
