package dev.okhsunrog.vpnhide

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Runs the language-independent golden vectors (kmod/shared/protocol_vectors.tsv)
 * against the Kotlin [Protocol] — the same file the C and Rust ports run, so a
 * divergence on any covered corner fails here (docs/protocol.md §8 Layer 1).
 */
class ProtocolTest {
    private fun vectorsFile(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        repeat(8) {
            val f = File(dir, "kmod/shared/protocol_vectors.tsv")
            if (f.isFile) return f
            dir = dir?.parentFile
        }
        error("protocol_vectors.tsv not found from ${System.getProperty("user.dir")}")
    }

    /** Decode the `\n \t \r \\ \xNN` escapes used in the vectors file. */
    private fun decode(s: String): String =
        buildString {
            var i = 0
            while (i < s.length) {
                if (s[i] == '\\' && i + 1 < s.length) {
                    when (s[i + 1]) {
                        'n' -> {
                            append('\n')
                            i += 2
                        }

                        't' -> {
                            append('\t')
                            i += 2
                        }

                        'r' -> {
                            append('\r')
                            i += 2
                        }

                        '\\' -> {
                            append('\\')
                            i += 2
                        }

                        'x' -> {
                            if (i + 3 < s.length) {
                                append(s.substring(i + 2, i + 4).toInt(16).toChar())
                                i += 4
                            } else {
                                append(s[i])
                                i++
                            }
                        }

                        else -> {
                            append(s[i])
                            i++
                        }
                    }
                } else {
                    append(s[i])
                    i++
                }
            }
        }

    private fun hexToLong(s: String): Long = java.lang.Long.parseUnsignedLong(s.trim().removePrefix("0x"), 16)

    private fun runCfg(
        input: String,
        expect: String,
    ) {
        val cfg = Protocol.parseConfig(decode(input))
        if (expect == "REJECT") {
            assertNull("expected REJECT for <$input>", cfg)
            return
        }
        requireNotNull(cfg) { "unexpected REJECT for <$input>" }
        val dbg =
            when (cfg.debug) {
                null -> -1
                false -> 0
                true -> 1
            }
        val got =
            buildString {
                append("debug=").append(dbg)
                for (t in cfg.targets) append(";0x").append(t.uid.toString(16)).append(":0x").append(t.hookmask.toString(16))
                for (p in cfg.prefixes) {
                    append(";pfx:")
                        .append(p.ifname)
                        .append(':')
                        .append(p.addrHex)
                        .append(':')
                        .append(p.prefixLen)
                    // rewrite mode only: the fake renders as a 5th colon field
                    if (p.fakeHex != null) append(':').append(p.fakeHex)
                }
                for (p in cfg.prefixes4) {
                    append(";pfx4:")
                        .append(p.ifname)
                        .append(':')
                        .append(p.addrHex)
                        .append(':')
                        .append(p.prefixLen)
                        .append(':')
                        .append(p.fakeHex)
                }
            }
        assertEquals("cfg <$input>", expect, got)
    }

    private fun runKind(
        input: String,
        expect: String,
    ) {
        val got =
            when (Protocol.peekKind(decode(input))) {
                Protocol.Kind.CONFIG -> "CONFIG"
                Protocol.Kind.STATS -> "STATS"
                Protocol.Kind.STATUS -> "STATUS"
                null -> "INVALID"
            }
        assertEquals("kind <$input>", expect, got)
    }

    private fun runStats(
        entries: String,
        expect: String,
    ) {
        val e =
            decode(entries).split(';').filter { it.isNotEmpty() }.map { grp ->
                val p = grp.split(',')
                Protocol.StatEntry(hexToLong(p[0]), hexToLong(p[1]), hexToLong(p[2]))
            }
        assertEquals("stats", decode(expect), Protocol.formatStats(e))
    }

    private fun runStatus(
        fields: String,
        expect: String,
    ) {
        val f = decode(fields).split(',')
        val s = Protocol.Status(hexToLong(f[0]), hexToLong(f[1]), hexToLong(f[2]), hexToLong(f[3]))
        assertEquals("status", decode(expect), Protocol.formatStatus(s))
    }

    private fun runClamp(
        full: String,
        outlen: String,
        expect: String,
    ) {
        val b = decode(full)
        val n = Protocol.clampToLine(b, outlen.toInt())
        assertEquals("clamp", decode(expect), b.substring(0, n))
    }

    @Test
    fun goldenVectors() {
        var count = 0
        vectorsFile().forEachLine { line ->
            if (line.isEmpty() || line.startsWith("#")) return@forEachLine
            val f = line.split('|')
            when (f[0]) {
                "cfg" -> runCfg(f[1], f[2])
                "kind" -> runKind(f[1], f[2])
                "stats" -> runStats(f[1], f[2])
                "status" -> runStatus(f[1], f[2])
                "clamp" -> runClamp(f[1], f[2], f[3])
                else -> error("unrecognised vector: $line")
            }
            count++
        }
        assertTrue("expected the full vector set, ran $count", count >= 30)
    }

    @Test
    fun configRoundTrips() {
        // formatConfig isn't covered by the shared vectors (no producer on the
        // C/Rust side), so pin the app's serialise direction with a round-trip.
        val targets = listOf(Protocol.Target(0x27faL, 0x3ffL), Protocol.Target(0x2947L, 0x4L))
        val text = Protocol.formatConfig(debug = true, targets = targets)
        assertEquals("vpnhide 1 config\ndebug 1\ntarget 0x27fa 0x3ff\ntarget 0x2947 0x4\n", text)
        val parsed = requireNotNull(Protocol.parseConfig(text))
        assertEquals(true, parsed.debug)
        assertEquals(targets, parsed.targets)
        // debug omitted ⇒ null on parse.
        val reparsed = requireNotNull(Protocol.parseConfig(Protocol.formatConfig(null, targets)))
        assertNull(reparsed.debug)
        // prefix records round-trip too (arbitrary masks above are intentional fixtures).
        val withPrefixes =
            Protocol.formatConfig(
                debug = true,
                targets = targets,
                prefixes = listOf(Protocol.PrefixRule("rmnet_data1", "24014900000000000000000000000000", 32)),
            )
        assertEquals(
            "vpnhide 1 config\ndebug 1\ntarget 0x27fa 0x3ff\ntarget 0x2947 0x4\nprefix rmnet_data1 24014900000000000000000000000000 0x20\n",
            withPrefixes,
        )
        assertEquals(
            listOf(Protocol.PrefixRule("rmnet_data1", "24014900000000000000000000000000", 32)),
            requireNotNull(Protocol.parseConfig(withPrefixes)).prefixes,
        )
        // rewrite mode (fake token) + prefix4 round-trip too.
        val withRewrite =
            Protocol.formatConfig(
                debug = false,
                targets = targets,
                prefixes =
                    listOf(
                        Protocol.PrefixRule(
                            "ccmni1",
                            "24014900000000000000000000000000",
                            32,
                            "240149007f3a9c215e881b4da2f06c19",
                        ),
                    ),
                prefixes4 = listOf(Protocol.Prefix4Rule("ccmni0", "64400000", 10, "6457172d")),
            )
        assertEquals(
            "vpnhide 1 config\ndebug 0\ntarget 0x27fa 0x3ff\ntarget 0x2947 0x4\n" +
                "prefix ccmni1 24014900000000000000000000000000 0x20 240149007f3a9c215e881b4da2f06c19\n" +
                "prefix4 ccmni0 64400000 0xa 6457172d\n",
            withRewrite,
        )
        val reparsedRewrite = requireNotNull(Protocol.parseConfig(withRewrite))
        assertEquals(
            listOf(
                Protocol.PrefixRule(
                    "ccmni1",
                    "24014900000000000000000000000000",
                    32,
                    "240149007f3a9c215e881b4da2f06c19",
                ),
            ),
            reparsedRewrite.prefixes,
        )
        assertEquals(
            listOf(Protocol.Prefix4Rule("ccmni0", "64400000", 10, "6457172d")),
            reparsedRewrite.prefixes4,
        )
    }
}
