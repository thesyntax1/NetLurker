package dev.netlurker.android.data

import org.json.JSONObject
import org.json.JSONTokener

/** A syntactically valid empty object is not a successful cached provider response. */
object CacheSchema {
    fun decode(payload: String, kind: String): JSONObject {
        val reader = JSONTokener(payload)
        val o = reader.nextValue() as? JSONObject ?: error("invalid cache object")
        require(reader.nextClean() == '\u0000') { "trailing cache data" }
        val strings: List<String>
        val booleans: List<String>
        val numbers: List<String>
        when (kind) {
            "geo" -> {
                strings = listOf("country", "countryCode", "city", "region", "isp", "org", "asn", "asname", "host")
                booleans = listOf("mobile", "proxy", "hosting"); numbers = emptyList()
            }
            "rdap" -> {
                strings = listOf("name", "org", "abuse", "cidr"); booleans = emptyList(); numbers = listOf("registered")
            }
            "cert" -> {
                strings = listOf("subject", "issuer", "sans", "serial", "sha256", "protocol", "cipher")
                booleans = listOf("selfSigned", "expired", "notYetValid", "nameMismatch")
                numbers = listOf("notBefore", "notAfter", "chain")
            }
            "banner" -> {
                strings = listOf("statusLine", "server", "via", "eolDetail"); booleans = listOf("eol"); numbers = listOf("ms")
            }
            else -> error("unknown cache schema")
        }
        require(strings.all { o.opt(it) is String } && booleans.all { o.opt(it) is Boolean }) { "invalid cache field type" }
        require(numbers.all {
            val n = o.opt(it) as? Number
            n != null && n.toDouble().isFinite() && n.toDouble() >= 0 &&
                n.toDouble() <= 9007199254740991.0 && n.toDouble() == kotlin.math.floor(n.toDouble())
        }) { "invalid cache number" }
        if (kind == "rdap") require(o.getString("cidr").isNotBlank()) { "missing network range" }
        if (kind == "cert") {
            require(o.getLong("notAfter") > o.getLong("notBefore") && o.getInt("chain") > 0)
            require(o.getString("sha256").replace(":", "").matches(Regex("[0-9a-fA-F]{64}")))
        }
        if (kind == "banner") require(o.getString("statusLine").startsWith("HTTP/"))
        return o
    }
}
