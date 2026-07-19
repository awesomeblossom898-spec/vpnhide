package dev.okhsunrog.vpnhide

// Entry-time validation for the global ipv6PrefixRules editor. Mirrors the
// activator's strict validator bit-for-bit (crates/activator/src/model.rs
// validate_ipv6_prefix_rules) so the UI never persists a list the activator
// would reject wholesale. The canonical-JSON parser stays best-effort by
// design; strictness lives here, at entry/persist time.

internal const val MAX_IPV6_PREFIX_RULES = 8

internal data class EditablePrefixRule(
    val iface: String = "",
    val prefix: String = "",
    val prefixLen: String = "",
)

internal enum class PrefixRuleField { Iface, Prefix, PrefixLen }

internal enum class PrefixRuleIssue(
    val field: PrefixRuleField?,
) {
    IfaceInvalid(PrefixRuleField.Iface),
    PrefixInvalid(PrefixRuleField.Prefix),
    PrefixLenInvalid(PrefixRuleField.PrefixLen),
    TooManyRules(null),
}

// ruleIndex is -1 (and issue TooManyRules) for list-level cap violations —
// never use it to index the rule list without checking issue first.
internal data class PrefixRuleError(
    val ruleIndex: Int,
    val issue: PrefixRuleIssue,
) {
    val field: PrefixRuleField?
        get() = issue.field
}

internal fun CanonicalIpv6PrefixRule.toEditable(): EditablePrefixRule =
    EditablePrefixRule(iface = iface, prefix = prefix, prefixLen = prefixLen.toString())

internal fun EditablePrefixRule.toCanonicalOrNull(): CanonicalIpv6PrefixRule? {
    if (prefixRuleFieldError(this) != null) return null
    return CanonicalIpv6PrefixRule(iface.trim(), prefix.trim(), prefixLen.trim().toInt())
}

// First invalid field of a single draft rule, or null when the rule is clean.
internal fun prefixRuleFieldError(rule: EditablePrefixRule): PrefixRuleField? =
    when {
        !isValidIface(rule.iface.trim()) -> PrefixRuleField.Iface
        !isValidIpv6Literal(rule.prefix.trim()) -> PrefixRuleField.Prefix
        rule.prefixLen.trim().toIntOrNull() !in 0..128 -> PrefixRuleField.PrefixLen
        else -> null
    }

// First error across the draft list (cap violation wins), or null when the
// whole list may be persisted.
internal fun validateEditablePrefixRules(rules: List<EditablePrefixRule>): PrefixRuleError? {
    if (rules.size > MAX_IPV6_PREFIX_RULES) return PrefixRuleError(-1, PrefixRuleIssue.TooManyRules)
    rules.forEachIndexed { index, rule ->
        when (prefixRuleFieldError(rule)) {
            PrefixRuleField.Iface -> return PrefixRuleError(index, PrefixRuleIssue.IfaceInvalid)
            PrefixRuleField.Prefix -> return PrefixRuleError(index, PrefixRuleIssue.PrefixInvalid)
            PrefixRuleField.PrefixLen -> return PrefixRuleError(index, PrefixRuleIssue.PrefixLenInvalid)
            null -> Unit
        }
    }
    return null
}

private fun isValidIface(iface: String): Boolean = iface.isNotEmpty() && iface.length <= 15 && iface.all { it.code in 0x21..0x7e }

// Strict IPv6 literal check mirroring Rust std::net::Ipv6Addr::from_str: one
// optional "::" compression, 1-4 hex digits per group, embedded dotted-quad
// IPv4 as the last group only (counts as two groups; octets 0-255 without
// leading zeros). No DNS, no zone ids, no brackets. Do NOT replace with
// InetAddress.getByName — it resolves non-numeric input over the network.
internal fun isValidIpv6Literal(value: String): Boolean {
    if (value.isEmpty()) return false
    val compression = value.indexOf("::")
    if (compression >= 0 && value.indexOf("::", compression + 2) >= 0) return false
    val head = if (compression >= 0) value.substring(0, compression) else value
    val tail = if (compression >= 0) value.substring(compression + 2) else ""
    // Rust parity: an embedded IPv4 quad must come from the tail, never the head.
    if (compression >= 0 && head.contains('.')) return false
    val groups = (splitGroups(head) ?: return false) + (splitGroups(tail) ?: return false)
    var count = 0
    groups.forEachIndexed { index, group ->
        if (group.length in 1..4 && group.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            count += 1
        } else {
            if (index != groups.lastIndex || !isValidIpv4Quad(group)) return false
            count += 2
        }
    }
    return if (compression >= 0) count < 8 else count == 8
}

private fun splitGroups(part: String): List<String>? {
    if (part.isEmpty()) return emptyList()
    val groups = part.split(":")
    if (groups.any { it.isEmpty() }) return null
    return groups
}

private fun isValidIpv4Quad(value: String): Boolean {
    val parts = value.split(".")
    if (parts.size != 4) return false
    return parts.all { part ->
        part.length in 1..3 &&
            part.all { it in '0'..'9' } &&
            !(part.length > 1 && part.startsWith("0")) &&
            part.toInt() <= 255
    }
}
