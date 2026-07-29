package dev.okhsunrog.vpnhide

// Address-rewrite matching for the system_server hook (and shared with the
// app's validation paths). Resolves canonical rule strings to network-order
// bytes ONCE at config-load time and answers "what fake, if any, should this
// interface address show" without any parsing on the hot path. Mirrors the
// kernel matcher semantics (kmod/shared/vpnhide_logic.h): interface name +
// top-prefixLen-bits equality, same fake bytes for every consumer. v6 fakes
// COMPOSE like the kernel's address rewrite: the stored fake's top 64 bits
// sit over the real address's low 64 (IID-follow), so the visible global
// address tracks the link-local IID like a stock interface.
//
// Parsing NEVER uses InetAddress.getByName — it resolves non-numeric input
// over the network. The literal parsers below mirror Rust's
// std::net::Ipv6Addr/Ipv4Addr::from_str acceptance (the activator's
// validators), exactly like isValidIpv6Literal does for the editor.

internal class PrefixRewriteRule(
    val iface: String,
    val prefixBytes: ByteArray,
    val prefixLen: Int,
    val fakeBytes: ByteArray,
) {
    /** The fake to show for [addrBytes] on [ifaceName], or null when this
     * rule doesn't match (different iface, different address family/length,
     * or outside the rule prefix). A 16-byte (v6) match composes fake top-64
     * over the address's real low-64; a 4-byte (v4) match substitutes whole. */
    fun fakeFor(
        ifaceName: String,
        addrBytes: ByteArray,
    ): ByteArray? {
        if (iface != ifaceName || addrBytes.size != prefixBytes.size) return null
        if (!topBitsEqual(prefixBytes, addrBytes, prefixLen)) return null
        return if (fakeBytes.size == 16) {
            fakeBytes.copyOfRange(0, 8) + addrBytes.copyOfRange(8, 16)
        } else {
            fakeBytes
        }
    }
}

/** First matching rule's fake, or null. Rule order is the canonical order —
 * overlapping rules resolve exactly like the kernel's first-match walk. */
internal fun List<PrefixRewriteRule>.fakeFor(
    ifaceName: String,
    addrBytes: ByteArray,
): ByteArray? = firstNotNullOfOrNull { it.fakeFor(ifaceName, addrBytes) }

/** Full-byte + boundary-mask equality of the top [bits] of [a] and [b] — the
 * same semantics as the wire matcher and the activator's top_bits_equal. */
internal fun topBitsEqual(
    a: ByteArray,
    b: ByteArray,
    bits: Int,
): Boolean {
    val full = bits / 8
    if (a.size < full || b.size < full) return false
    for (i in 0 until full) {
        if (a[i] != b[i]) return false
    }
    val rem = bits % 8
    if (rem == 0) return true
    if (a.size <= full || b.size <= full) return false
    val mask = 0xff shl (8 - rem) and 0xff
    return a[full].toInt() and mask == b[full].toInt() and mask
}

/** A rewrite rule from a canonical v6 rule, or null when it isn't a valid
 * rewrite (hide mode, missing/malformed fake, or fake outside the rule
 * prefix). Malformed rules are DROPPED, never applied half-way. */
internal fun CanonicalIpv6PrefixRule.toRewriteRuleOrNull(): PrefixRewriteRule? {
    if (mode != PrefixRuleMode.Rewrite) return null
    val fake = fake ?: return null
    val prefixBytes = parseIpv6LiteralBytes(prefix) ?: return null
    val fakeBytes = parseIpv6LiteralBytes(fake) ?: return null
    if (!topBitsEqual(prefixBytes, fakeBytes, prefixLen)) return null
    return PrefixRewriteRule(iface, prefixBytes, prefixLen, fakeBytes)
}

/** A rewrite rule from a canonical v4 rule (rewrite-only by schema), or null
 * when malformed. NO containment requirement: a v4 fake may be any unicast
 * address (e.g. the proxy exit IP under Veil's exit-sync) — plausibility is
 * the editor's concern; the matcher rewrites whatever the config carries. */
internal fun CanonicalIpv4Rule.toRewriteRuleOrNull(): PrefixRewriteRule? {
    val prefixBytes = parseIpv4QuadBytes(prefix) ?: return null
    val fakeBytes = parseIpv4QuadBytes(fake) ?: return null
    return PrefixRewriteRule(iface, prefixBytes, prefixLen, fakeBytes)
}

/** Strict RFC 4291 literal → 16 network-order bytes, or null. Acceptance is
 * identical to isValidIpv6Literal (reused as the gate); this only expands
 * compression and hex groups into bytes. */
internal fun parseIpv6LiteralBytes(value: String): ByteArray? {
    if (!isValidIpv6Literal(value)) return null
    val compression = value.indexOf("::")
    val head = if (compression >= 0) value.substring(0, compression) else value
    val tail = if (compression >= 0) value.substring(compression + 2) else ""
    val headBytes = ipv6GroupsToBytes(head) ?: return null
    val tailBytes = ipv6GroupsToBytes(tail) ?: return null
    val total = headBytes.size + tailBytes.size
    return if (compression >= 0) {
        if (total >= 16) return null
        headBytes + ByteArray(16 - total) + tailBytes
    } else {
        if (total != 16) return null
        headBytes + tailBytes
    }
}

private fun ipv6GroupsToBytes(part: String): ByteArray? {
    if (part.isEmpty()) return ByteArray(0)
    val groups = part.split(":")
    val out = ByteArray(groups.size * 2 + 2)
    var pos = 0
    groups.forEachIndexed { index, group ->
        if (group.contains('.')) {
            if (index != groups.lastIndex) return null
            val quad = parseIpv4QuadBytes(group) ?: return null
            quad.copyInto(out, pos)
            pos += quad.size
        } else {
            val v = group.toIntOrNull(16) ?: return null
            out[pos] = (v shr 8).toByte()
            out[pos + 1] = (v and 0xff).toByte()
            pos += 2
        }
    }
    return out.copyOf(pos)
}

/** Strict dotted-quad → 4 network-order bytes, or null. Rust parity: octets
 * 0-255, no leading zeros on multi-digit octets. */
internal fun parseIpv4QuadBytes(value: String): ByteArray? {
    val parts = value.split(".")
    if (parts.size != 4) return null
    val out = ByteArray(4)
    parts.forEachIndexed { index, part ->
        if (part.length !in 1..3 || !part.all { it in '0'..'9' }) return null
        if (part.length > 1 && part.startsWith("0")) return null
        val v = part.toInt()
        if (v > 255) return null
        out[index] = v.toByte()
    }
    return out
}
