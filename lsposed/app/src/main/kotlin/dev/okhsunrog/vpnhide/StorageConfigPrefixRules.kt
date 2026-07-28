package dev.okhsunrog.vpnhide

import org.json.JSONObject

// Canonical-JSON schema for the prefix rules (v6 hide/rewrite + v4 rewrite).
// Extracted from StorageConfig.kt (shrink-only line budget); the parse side is
// best-effort (one malformed entry is skipped, never unwinds the config), the
// write side emits non-default keys only so hide rules stay byte-identical to
// the pre-rewrite schema.

internal enum class PrefixRuleMode(
    val jsonName: String,
) {
    Hide("hide"),
    Rewrite("rewrite"),
    ;

    companion object {
        fun fromJson(value: String): PrefixRuleMode = entries.firstOrNull { it.jsonName == value } ?: Hide
    }
}

internal data class CanonicalIpv6PrefixRule(
    val iface: String,
    val prefix: String,
    val prefixLen: Int,
    val mode: PrefixRuleMode = PrefixRuleMode.Hide,
    // Rewrite target; non-null only when mode == Rewrite (enforced at parse).
    val fake: String? = null,
)

// IPv4 rules are rewrite-only — hiding the device's only v4 address would
// wedge networking — so [fake] is required, never null.
internal data class CanonicalIpv4Rule(
    val iface: String,
    val prefix: String,
    val prefixLen: Int,
    val fake: String,
)

internal fun parseIpv6PrefixRules(root: JSONObject): List<CanonicalIpv6PrefixRule> {
    val array = root.optJSONArray("ipv6PrefixRules") ?: return emptyList()
    // Best-effort, same philosophy as parsePortPolicy: one malformed entry must
    // not throw and unwind the WHOLE canonical config — skip it and keep the
    // valid siblings. Strict validation (IPv6-ness, printable-ASCII iface) is
    // the activator's job at projection time, not the writer's.
    return (0 until array.length()).mapNotNull { idx ->
        val obj = array.optJSONObject(idx) ?: return@mapNotNull null
        runCatching {
            val iface = obj.optString("iface", "")
            val prefix = obj.optString("prefix", "")
            val prefixLen = obj.optInt("prefixLen", -1)
            val mode = PrefixRuleMode.fromJson(obj.optString("mode", PrefixRuleMode.Hide.jsonName))
            val fake = obj.optString("fake", "").takeIf { it.isNotBlank() }
            require(iface.isNotBlank() && iface.length < 16) { "bad iface" }
            require(prefix.isNotBlank()) { "bad prefix" }
            require(prefixLen in 0..128) { "bad prefixLen" }
            // Same invariants as the activator's strict validation: rewrite
            // without a fake is meaningless, hide carrying one is contradictory
            // — both are malformed entries and get skipped, not the config.
            require(mode != PrefixRuleMode.Rewrite || fake != null) { "rewrite needs fake" }
            require(mode != PrefixRuleMode.Hide || fake == null) { "hide must not carry fake" }
            CanonicalIpv6PrefixRule(iface, prefix, prefixLen, mode, fake)
        }.getOrNull()
    }
}

internal fun parseIpv4Rules(root: JSONObject): List<CanonicalIpv4Rule> {
    val array = root.optJSONArray("ipv4Rules") ?: return emptyList()
    // Same best-effort philosophy as parseIpv6PrefixRules.
    return (0 until array.length()).mapNotNull { idx ->
        val obj = array.optJSONObject(idx) ?: return@mapNotNull null
        runCatching {
            val iface = obj.optString("iface", "")
            val prefix = obj.optString("prefix", "")
            val prefixLen = obj.optInt("prefixLen", -1)
            val fake = obj.optString("fake", "")
            require(iface.isNotBlank() && iface.length < 16) { "bad iface" }
            require(prefix.isNotBlank()) { "bad prefix" }
            require(prefixLen in 0..32) { "bad prefixLen" }
            require(fake.isNotBlank()) { "ipv4 rule is rewrite-only" }
            CanonicalIpv4Rule(iface, prefix, prefixLen, fake)
        }.getOrNull()
    }
}

internal fun StringBuilder.appendIpv6PrefixRules(rules: List<CanonicalIpv6PrefixRule>) {
    append("  \"ipv6PrefixRules\": [\n")
    rules.forEachIndexed { index, rule ->
        append("    { \"iface\": ")
        appendJsonString(rule.iface)
        append(", \"prefix\": ")
        appendJsonString(rule.prefix)
        append(", \"prefixLen\": ")
        append(rule.prefixLen)
        // Non-default keys only (same conditional-emission pattern as
        // PortRule.end): hide rules stay byte-identical to the pre-rewrite
        // schema, and fake appears only alongside it.
        if (rule.mode != PrefixRuleMode.Hide) {
            append(", \"mode\": ")
            appendJsonString(rule.mode.jsonName)
        }
        if (rule.fake != null) {
            append(", \"fake\": ")
            appendJsonString(rule.fake)
        }
        append(" }")
        if (index != rules.size - 1) append(',')
        append('\n')
    }
    append("  ],\n")
}

internal fun StringBuilder.appendIpv4Rules(rules: List<CanonicalIpv4Rule>) {
    append("  \"ipv4Rules\": [\n")
    rules.forEachIndexed { index, rule ->
        append("    { \"iface\": ")
        appendJsonString(rule.iface)
        append(", \"prefix\": ")
        appendJsonString(rule.prefix)
        append(", \"prefixLen\": ")
        append(rule.prefixLen)
        append(", \"fake\": ")
        appendJsonString(rule.fake)
        append(" }")
        if (index != rules.size - 1) append(',')
        append('\n')
    }
    append("  ],\n")
}
