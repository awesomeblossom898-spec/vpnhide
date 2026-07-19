package dev.okhsunrog.vpnhide

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Ipv6PrefixRulesDataTest {
    private fun rule(
        iface: String = "rmnet_data0",
        prefix: String = "2409:40e3::",
        prefixLen: String = "32",
    ) = EditablePrefixRule(iface = iface, prefix = prefix, prefixLen = prefixLen)

    @Test
    fun `valid rules pass validation`() {
        val rules = listOf(rule(), rule(iface = "tun0", prefix = "::ffff:1.2.3.4", prefixLen = "128"), rule(prefix = "::", prefixLen = "0"))
        assertNull(validateEditablePrefixRules(rules))
    }

    @Test
    fun `iface must be 1 to 15 printable ascii chars`() {
        assertEquals(PrefixRuleField.Iface, validateEditablePrefixRules(listOf(rule(iface = "")))?.field)
        assertEquals(PrefixRuleField.Iface, validateEditablePrefixRules(listOf(rule(iface = "sixteen_char_if0")))?.field)
        assertEquals(PrefixRuleField.Iface, validateEditablePrefixRules(listOf(rule(iface = "rmnet data0")))?.field)
        assertEquals(PrefixRuleField.Iface, validateEditablePrefixRules(listOf(rule(iface = "rmnet\tdata0")))?.field)
        assertEquals(PrefixRuleField.Iface, validateEditablePrefixRules(listOf(rule(iface = "rmnet_dataÄ")))?.field)
        assertNull(validateEditablePrefixRules(listOf(rule(iface = "fifteen_char_if"))))
    }

    @Test
    fun `prefix must be a valid ipv6 literal`() {
        val good =
            listOf(
                "::",
                "2409:40e3::",
                "fe80::1",
                "::ffff:1.2.3.4",
                "0:0:0:0:0:ffff:1.2.3.4",
                "abcd::1.2.3.4",
                "2001:db8:85a3:8d3:1319:8a2e:370:7348",
                "1:2:3:4:5:6:7::",
                "::1:2:3:4:5:6:7",
                "ABCD::ef01",
            )
        good.forEach { assertTrue("expected valid: $it", isValidIpv6Literal(it)) }
        val bad =
            listOf(
                "",
                "1.2.3.4",
                "gg::1",
                "1::2::3",
                "fe80::1%eth0",
                "12345::",
                ":1::2",
                "1::2:",
                "1:2:3:4:5:6:7:8:9",
                "1:2:3:4:5:6:7:8::",
                "0:0:0:0:0:ffff:1.2.3.256",
                "0:0:0:0:0:ffff:01.2.3.4",
                "::ffff:1.2.3",
                "1.2.3.4::",
                "abcd:1.2.3.4::",
                "2409:40e3::/32",
            )
        bad.forEach { assertFalse("expected invalid: $it", isValidIpv6Literal(it)) }
        assertEquals(PrefixRuleField.Prefix, validateEditablePrefixRules(listOf(rule(prefix = "nope")))?.field)
    }

    @Test
    fun `prefixLen must be within 0 to 128`() {
        assertEquals(PrefixRuleField.PrefixLen, validateEditablePrefixRules(listOf(rule(prefixLen = "")))?.field)
        assertEquals(PrefixRuleField.PrefixLen, validateEditablePrefixRules(listOf(rule(prefixLen = "abc")))?.field)
        assertEquals(PrefixRuleField.PrefixLen, validateEditablePrefixRules(listOf(rule(prefixLen = "-1")))?.field)
        assertEquals(PrefixRuleField.PrefixLen, validateEditablePrefixRules(listOf(rule(prefixLen = "129")))?.field)
        assertNull(validateEditablePrefixRules(listOf(rule(prefixLen = "0"))))
        assertNull(validateEditablePrefixRules(listOf(rule(prefixLen = "128"))))
    }

    @Test
    fun `more than 8 rules are rejected`() {
        val rules = (1..9).map { rule(iface = "rmnet_data$it") }
        assertEquals(PrefixRuleIssue.TooManyRules, validateEditablePrefixRules(rules)?.issue)
        assertNull(validateEditablePrefixRules((1..8).map { rule(iface = "rmnet_data$it") }))
    }

    @Test
    fun `first failing rule and field is reported`() {
        val rules = listOf(rule(), rule(prefix = "bad"), rule(iface = "bad iface"))
        val error = validateEditablePrefixRules(rules)
        assertEquals(1, error?.ruleIndex)
        assertEquals(PrefixRuleIssue.PrefixInvalid, error?.issue)
        assertEquals(PrefixRuleField.Prefix, error?.field)
    }

    @Test
    fun `editable and canonical forms round trip`() {
        val canonical = CanonicalIpv6PrefixRule(iface = "rmnet_data2", prefix = "2409:4123::", prefixLen = 32)
        val editable = canonical.toEditable()
        assertEquals(EditablePrefixRule("rmnet_data2", "2409:4123::", "32"), editable)
        assertEquals(canonical, editable.toCanonicalOrNull())
        assertNull(EditablePrefixRule("a", "b", "x").toCanonicalOrNull())
    }

    @Test
    fun `whitespace padded fields validate and persist trimmed`() {
        val padded = rule(iface = " rmnet_data0 ", prefix = " 2409:40e3:: ", prefixLen = " 32 ")
        assertNull(validateEditablePrefixRules(listOf(padded)))
        assertEquals(CanonicalIpv6PrefixRule("rmnet_data0", "2409:40e3::", 32), padded.toCanonicalOrNull())
        assertNull(EditablePrefixRule("rmnet_data0", "2409:40e3::", "999").toCanonicalOrNull())
    }
}
