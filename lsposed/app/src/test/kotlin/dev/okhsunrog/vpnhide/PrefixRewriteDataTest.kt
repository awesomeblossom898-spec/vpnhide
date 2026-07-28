package dev.okhsunrog.vpnhide

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PrefixRewriteDataTest {
    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun `ipv6 literal parser expands full compressed and embedded forms`() {
        assertArrayEquals(hex("24014900") + ByteArray(12), parseIpv6LiteralBytes("2401:4900::"))
        assertArrayEquals(ByteArray(15) + 0x01.toByte(), parseIpv6LiteralBytes("::1"))
        assertArrayEquals(ByteArray(16), parseIpv6LiteralBytes("::"))
        // 2001:db8:85a3::8a2e:370:7334
        assertArrayEquals(
            hex("20010db885a3000000008a2e03707334"),
            parseIpv6LiteralBytes("2001:db8:85a3::8a2e:370:7334"),
        )
        // Embedded dotted-quad tail counts as the last two groups.
        assertArrayEquals(ByteArray(10) + byteArrayOf(0, 0, 1, 2, 3, 4), parseIpv6LiteralBytes("::1.2.3.4"))
        // Full 8-group form.
        assertArrayEquals(ByteArray(14) + byteArrayOf(0xab.toByte(), 0xcd.toByte()), parseIpv6LiteralBytes("0:0:0:0:0:0:0:abcd"))
    }

    @Test
    fun `ipv6 literal parser rejects malformed input`() {
        assertNull(parseIpv6LiteralBytes(""))
        assertNull(parseIpv6LiteralBytes("2401:4900:::1"))
        assertNull(parseIpv6LiteralBytes("12345::"))
        assertNull(parseIpv6LiteralBytes("1:2:3:4:5:6:7:8:9"))
        assertNull(parseIpv6LiteralBytes("1:2:3:4:5:6:7")) // no compression: must be 8 groups
        assertNull(parseIpv6LiteralBytes("gg::1"))
        assertNull(parseIpv6LiteralBytes("::256.1.2.3"))
        assertNull(parseIpv6LiteralBytes("::01.2.3.4")) // leading-zero quad, Rust parity
        assertNull(parseIpv6LiteralBytes("1.2.3.4::")) // quad only as last group
    }

    @Test
    fun `ipv4 quad parser is strict`() {
        assertArrayEquals(byteArrayOf(100, 64, 0, 0), parseIpv4QuadBytes("100.64.0.0"))
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), parseIpv4QuadBytes("0.0.0.0"))
        assertNull(parseIpv4QuadBytes("100.64.0"))
        assertNull(parseIpv4QuadBytes("100.64.0.0.1"))
        assertNull(parseIpv4QuadBytes("100.64.0.256"))
        assertNull(parseIpv4QuadBytes("010.64.0.0"))
        assertNull(parseIpv4QuadBytes("100.64.0.x"))
    }

    @Test
    fun `topBitsEqual honours full bytes and boundary mask`() {
        val a = byteArrayOf(0x24, 0x01, 0x49, 0x00)
        val same32 = byteArrayOf(0x24, 0x01, 0x49, 0x00)
        val diff32 = byteArrayOf(0x24, 0x01, 0x49, 0x01)
        assertTrue(topBitsEqual(a, same32, 32))
        assertFalse(topBitsEqual(a, diff32, 32))
        // /10 boundary: 100.64.0.0 vs 100.87.23.45 share the top 10 bits
        // (100.01xxxxxx), 100.128.0.0 does not (100.10xxxxxx).
        val cgnatBase = byteArrayOf(100, 64, 0, 0)
        val cgnatFake = byteArrayOf(100, 87, 23, 45)
        val outside = byteArrayOf(100, 128.toByte(), 0, 0)
        assertTrue(topBitsEqual(cgnatBase, cgnatFake, 10))
        assertFalse(topBitsEqual(cgnatBase, outside, 10))
        assertTrue(topBitsEqual(cgnatBase, cgnatBase, 0))
    }

    @Test
    fun `rewrite rule matches iface and prefix only`() {
        val rule =
            PrefixRewriteRule(
                iface = "ccmni1",
                prefixBytes = parseIpv4QuadBytes("100.64.0.0")!!,
                prefixLen = 10,
                fakeBytes = parseIpv4QuadBytes("100.87.23.45")!!,
            )
        assertArrayEquals(
            parseIpv4QuadBytes("100.87.23.45"),
            rule.fakeFor("ccmni1", parseIpv4QuadBytes("100.124.146.11")!!),
        )
        assertNull(rule.fakeFor("ccmni0", parseIpv4QuadBytes("100.124.146.11")!!))
        assertNull(rule.fakeFor("ccmni1", parseIpv4QuadBytes("192.168.1.5")!!))
        // Address-family length mismatch never matches.
        assertNull(rule.fakeFor("ccmni1", ByteArray(16)))
    }

    @Test
    fun `canonical v6 rule resolves only in rewrite mode with contained fake`() {
        val hide = CanonicalIpv6PrefixRule("ccmni1", "2401:4900::", 32)
        assertNull(hide.toRewriteRuleOrNull())
        val rewrite =
            CanonicalIpv6PrefixRule(
                "ccmni1",
                "2401:4900::",
                32,
                PrefixRuleMode.Rewrite,
                "2401:4900:7f3a:9c21:5e88:1b4d:a2f0:6c19",
            )
        val rule = rewrite.toRewriteRuleOrNull()
        assertEquals("ccmni1", rule?.iface)
        assertEquals(32, rule?.prefixLen)
        // Fake outside the rule prefix is dropped, not applied.
        val escaped =
            CanonicalIpv6PrefixRule(
                "ccmni1",
                "2401:4900::",
                32,
                PrefixRuleMode.Rewrite,
                "2401:4901::1",
            )
        assertNull(escaped.toRewriteRuleOrNull())
        // Malformed fake is dropped.
        val malformed = rewrite.copy(fake = "not-an-address")
        assertNull(malformed.toRewriteRuleOrNull())
    }

    @Test
    fun `canonical v4 rule resolves with contained fake`() {
        val rule = CanonicalIpv4Rule("ccmni0", "100.64.0.0", 10, "100.87.23.45").toRewriteRuleOrNull()
        assertEquals("ccmni0", rule?.iface)
        assertArrayEquals(parseIpv4QuadBytes("100.87.23.45"), rule?.fakeBytes)
        assertNull(CanonicalIpv4Rule("ccmni0", "100.64.0.0", 10, "192.168.0.1").toRewriteRuleOrNull())
        assertNull(CanonicalIpv4Rule("ccmni0", "100.64.0.0", 10, "junk").toRewriteRuleOrNull())
    }

    @Test
    fun `list resolver picks first matching rule`() {
        val rules =
            listOf(
                CanonicalIpv4Rule("ccmni0", "100.64.0.0", 10, "100.87.23.45").toRewriteRuleOrNull()!!,
                CanonicalIpv4Rule("ccmni1", "100.64.0.0", 10, "100.99.1.2").toRewriteRuleOrNull()!!,
            )
        assertArrayEquals(
            parseIpv4QuadBytes("100.99.1.2"),
            rules.fakeFor("ccmni1", parseIpv4QuadBytes("100.70.0.9")!!),
        )
        assertNull(rules.fakeFor("wlan0", parseIpv4QuadBytes("100.70.0.9")!!))
        assertNull(rules.fakeFor("ccmni0", parseIpv4QuadBytes("10.0.0.2")!!))
    }
}
