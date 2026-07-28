package dev.okhsunrog.vpnhide

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Schema tests for the rewrite extension: mode/fake on ipv6PrefixRules and
 * the rewrite-only ipv4Rules array (StorageConfigPrefixRules.kt). Split from
 * StorageConfigTest (detekt LargeClass). */
class StorageConfigPrefixRulesTest {
    @Test
    fun `canonical config parses rewrite mode fakes and ipv4 rules`() {
        val cfg =
            requireNotNull(
                parseCanonicalConfig(
                    """
                    {
                      "version": 1,
                      "apps": {},
                      "ipv6PrefixRules": [
                        { "iface": "ccmni1", "prefix": "2401:4900::", "prefixLen": 32 },
                        { "iface": "ccmni0", "prefix": "2401:4900::", "prefixLen": 32,
                          "mode": "rewrite", "fake": "2401:4900:7f3a:9c21:5e88:1b4d:a2f0:6c19" },
                        { "iface": "ccmni2", "prefix": "2401:4900::", "prefixLen": 32, "mode": "rewrite" },
                        { "iface": "ccmni3", "prefix": "2401:4900::", "prefixLen": 32, "fake": "2401:4900::1" }
                      ],
                      "ipv4Rules": [
                        { "iface": "ccmni1", "prefix": "100.64.0.0", "prefixLen": 10, "fake": "100.87.23.45" },
                        { "iface": "ccmni0", "prefix": "100.64.0.0", "prefixLen": 10 },
                        { "iface": "ccmni0", "prefix": "100.64.0.0", "prefixLen": 40, "fake": "100.87.23.45" }
                      ]
                    }
                    """.trimIndent(),
                ),
            )

        // Missing mode defaults to hide; rewrite-without-fake and hide-with-fake
        // are malformed entries and get skipped, valid siblings survive.
        assertEquals(
            listOf(
                CanonicalIpv6PrefixRule(iface = "ccmni1", prefix = "2401:4900::", prefixLen = 32),
                CanonicalIpv6PrefixRule(
                    iface = "ccmni0",
                    prefix = "2401:4900::",
                    prefixLen = 32,
                    mode = PrefixRuleMode.Rewrite,
                    fake = "2401:4900:7f3a:9c21:5e88:1b4d:a2f0:6c19",
                ),
            ),
            cfg.ipv6PrefixRules,
        )
        // v4: missing fake and out-of-range plen dropped.
        assertEquals(
            listOf(CanonicalIpv4Rule(iface = "ccmni1", prefix = "100.64.0.0", prefixLen = 10, fake = "100.87.23.45")),
            cfg.ipv4Rules,
        )
    }

    @Test
    fun `canonical json emits rewrite keys conditionally and round trips`() {
        val cfg =
            CanonicalConfig(
                ipv6PrefixRules =
                    listOf(
                        CanonicalIpv6PrefixRule(iface = "ccmni1", prefix = "2401:4900::", prefixLen = 32),
                        CanonicalIpv6PrefixRule(
                            iface = "ccmni0",
                            prefix = "2401:4900::",
                            prefixLen = 32,
                            mode = PrefixRuleMode.Rewrite,
                            fake = "2401:4900:7f3a:9c21:5e88:1b4d:a2f0:6c19",
                        ),
                    ),
                ipv4Rules =
                    listOf(
                        CanonicalIpv4Rule(iface = "ccmni1", prefix = "100.64.0.0", prefixLen = 10, fake = "100.87.23.45"),
                    ),
            )

        val json = canonicalConfigJson(cfg)

        // Hide rule stays byte-identical to the pre-rewrite schema.
        assertTrue(json.contains("{ \"iface\": \"ccmni1\", \"prefix\": \"2401:4900::\", \"prefixLen\": 32 }"))
        assertTrue(json.contains("\"mode\": \"rewrite\""))
        assertTrue(json.contains("\"ipv4Rules\": ["))
        assertEquals(cfg, requireNotNull(parseCanonicalConfig(json)))
        assertTrue(!canonicalConfigJson(CanonicalConfig()).contains("\"ipv4Rules\""))
    }

    @Test
    fun `builder preserves ipv4 rules when rebuilding`() {
        val rules = listOf(CanonicalIpv4Rule(iface = "ccmni1", prefix = "100.64.0.0", prefixLen = 10, fake = "100.87.23.45"))
        val existing = CanonicalConfig(ipv4Rules = rules)

        val cfg =
            buildCanonicalConfig(
                debug = false,
                javaPkgs = emptySet(),
                nativePkgs = setOf("com.bank"),
                hiddenPkgs = emptySet(),
                observerPkgs = emptySet(),
                portsPkgs = emptySet(),
                existing = existing,
            )

        assertEquals(rules, cfg.ipv4Rules)
    }
}
