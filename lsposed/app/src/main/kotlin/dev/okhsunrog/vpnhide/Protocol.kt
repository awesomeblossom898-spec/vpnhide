package dev.okhsunrog.vpnhide

/**
 * Kotlin side of the vpnhide control/stats wire format (docs/protocol.md §4).
 *
 * Mirrors the freestanding C (`kmod/shared/vpnhide_logic.h`) and the Rust
 * (`zygisk/src/protocol.rs`) byte for byte; parity is held by the shared golden
 * vectors (`kmod/shared/protocol_vectors.tsv`), run by ProtocolTest. This is the
 * "thick" end (protocol §1.4): the app **serialises** config snapshots into
 * every channel and **parses** stats/status back; the `system_server` LSPosed
 * hook **parses** config from its file. So both directions live here.
 *
 * Numbers are carried as [Long]: `uid`/`hookmask`/`hook_id` are u32 (always
 * non-negative here); `count` is u64 carried as raw bits (use the unsigned
 * formatter/parser), so a full-range counter round-trips exactly.
 */
internal object Protocol {
    const val VERSION = 1

    enum class Kind { CONFIG, STATS, STATUS }

    data class Target(
        val uid: Long,
        val hookmask: Long,
    )

    /** One `prefix <ifname> <addr32hex> <plen>` record (§4.3, global scope).
     * [addrHex] is the normalised lowercase 32-hex form of the 16 network-order
     * bytes (liberal-in case on the wire, normalised at parse). */
    data class PrefixRule(
        val ifname: String,
        val addrHex: String,
        val prefixLen: Long,
    )

    /** A parsed config. [debug] is null when no `debug` line was present
     * ("unchanged from default", §4.3), else the flag. */
    data class Config(
        val debug: Boolean?,
        val targets: List<Target>,
        val prefixes: List<PrefixRule>,
    )

    data class StatEntry(
        val uid: Long,
        val hookId: Long,
        val count: Long,
    )

    data class Status(
        val backend: Long,
        val kver: Long,
        val hooks: Long,
        val error: Long,
    )

    /**
     * Self-documenting banner a read endpoint prepends to its snapshot
     * (§OPEN-7). It's a `#` comment line, ignored by every parser.
     */
    const val READ_BANNER = "# vpnhide v1 — a WRITE replaces ENTIRE state; this read is status+stats\n"

    // ── lexical helpers (§4.1) ────────────────────────────────────────────

    private fun isSep(c: Char) = c == ' ' || c == '\t'

    private fun isAsciiPrintable(c: Char) = c.code in 0x20..0x7e

    /** Split on `\n`, stripping a trailing `\r` per line (CRLF → LF). */
    private fun lines(text: String): List<String> = text.split('\n').map { it.removeSuffix("\r") }

    /** Blank line or a `#` comment — ignored on both header search and records. */
    private fun isIgnorable(line: String): Boolean {
        val s = line.indexOfFirst { !isSep(it) }
        return s < 0 || line[s] == '#'
    }

    /** A line is acceptable only if every byte is printable ASCII or a tab. */
    private fun isAscii(line: String) = line.all { isAsciiPrintable(it) || it == '\t' }

    private fun contentAfterWs(line: String): String = line.substring(line.indexOfFirst { !isSep(it) })

    private fun tokens(content: String): List<String> = content.split(' ', '\t').filter { it.isNotEmpty() }

    /**
     * Parse the one numeric primitive (§4.4): `0x` (mandatory) + ≥1 hex digit,
     * any case; reject if it overflows `bits` (32/64). Returns the value as raw
     * Long bits, or null on any malformation.
     */
    private fun parseHex(
        tok: String,
        bits: Int,
    ): Long? {
        if (tok.length < 3 || tok[0] != '0' || (tok[1] != 'x' && tok[1] != 'X')) return null
        val max = if (bits >= 64) ULong.MAX_VALUE else 0xffffffffuL
        var v = 0uL
        for (c in tok.substring(2)) {
            val d =
                when (c) {
                    in '0'..'9' -> c - '0'
                    in 'a'..'f' -> c - 'a' + 10
                    in 'A'..'F' -> c - 'A' + 10
                    else -> return null
                }.toULong()
            if (v > (max - d) / 16uL) return null // width overflow
            v = v * 16uL + d
        }
        return v.toLong()
    }

    /** An interface-name token: 1..15 chars (record lines are already
     * ASCII-clean). Empty or >= 16 → null. */
    private fun parseIfname(tok: String): String? = tok.takeIf { it.isNotEmpty() && it.length < 16 }

    /** The 16-byte prefix address: exactly 32 hex chars, liberal-in case,
     * normalised lowercase-out (§4.4). */
    private fun parseAddr32(tok: String): String? =
        tok
            .takeIf { t -> t.length == 32 && t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } }
            ?.lowercase()

    /** Always lowercase out (§4.4: liberal-in / strict-out). Unsigned so a u64
     * value with the high bit set still renders correctly. */
    private fun hex(v: Long): String = "0x" + java.lang.Long.toUnsignedString(v, 16)

    // ── header (§4.2) ─────────────────────────────────────────────────────

    private data class Header(
        val kind: Kind,
        val records: List<String>,
    )

    private fun parseHeader(text: String): Header? {
        val ls = lines(text)
        for (i in ls.indices) {
            val line = ls[i]
            if (isIgnorable(line)) continue // blank / comment before the header is fine
            // first significant line == the mandatory header
            if (!isAscii(line)) return null
            val toks = tokens(contentAfterWs(line))
            if (toks.getOrNull(0) != "vpnhide") return null
            val ver = toks.getOrNull(1)?.toIntOrNull() ?: return null
            if (ver > VERSION) return null
            val kind =
                when (toks.getOrNull(2)) {
                    "config" -> Kind.CONFIG
                    "stats" -> Kind.STATS
                    "status" -> Kind.STATUS
                    else -> return null
                }
            return Header(kind, ls.subList(i + 1, ls.size))
        }
        return null
    }

    fun peekKind(text: String): Kind? = parseHeader(text)?.kind

    /** Records that are significant (not blank/comment) and ASCII-clean (§4.5). */
    private inline fun forEachRecord(
        records: List<String>,
        body: (List<String>) -> Unit,
    ) {
        for (line in records) {
            if (isIgnorable(line) || !isAscii(line)) continue
            body(tokens(contentAfterWs(line)))
        }
    }

    // ── config (§4.3) ─────────────────────────────────────────────────────

    /** Parse a `config` payload, or null if rejected whole (bad/missing header,
     * version too new, wrong kind). Duplicate uid ⇒ last wins; unknown keywords
     * and malformed lines are skipped. */
    fun parseConfig(text: String): Config? {
        val h = parseHeader(text) ?: return null
        if (h.kind != Kind.CONFIG) return null
        var debug: Boolean? = null
        val targets = mutableListOf<Target>()
        val prefixes = mutableListOf<PrefixRule>()
        forEachRecord(h.records) { toks ->
            when (toks.getOrNull(0)) {
                "debug" -> {
                    when (toks.getOrNull(1)) {
                        "0" -> {
                            debug = false
                        }

                        "1" -> {
                            debug = true
                        }

                        else -> {} // malformed flag ⇒ skip
                    }
                }

                "target" -> {
                    val uid = toks.getOrNull(1)?.let { parseHex(it, 32) }
                    val hm = toks.getOrNull(2)?.let { parseHex(it, 32) }
                    if (uid != null && hm != null) setTarget(targets, uid, hm)
                }

                "prefix" -> {
                    val ifname = toks.getOrNull(1)?.let(::parseIfname)
                    val addr = toks.getOrNull(2)?.let(::parseAddr32)
                    val plen = toks.getOrNull(3)?.let { parseHex(it, 32) }
                    if (ifname != null && addr != null && plen != null && plen <= 128) {
                        prefixes += PrefixRule(ifname, addr, plen)
                    }
                }
            }
        }
        return Config(debug, targets, prefixes)
    }

    private fun setTarget(
        targets: MutableList<Target>,
        uid: Long,
        hookmask: Long,
    ) {
        val idx = targets.indexOfFirst { it.uid == uid }
        if (idx >= 0) targets[idx] = Target(uid, hookmask) else targets += Target(uid, hookmask)
    }

    fun formatConfig(
        debug: Boolean?,
        targets: List<Target>,
        prefixes: List<PrefixRule> = emptyList(),
    ): String =
        buildString {
            append("vpnhide ").append(VERSION).append(" config\n")
            if (debug != null) append("debug ").append(if (debug) "1" else "0").append('\n')
            for (t in targets) {
                append("target ")
                    .append(hex(t.uid))
                    .append(' ')
                    .append(hex(t.hookmask))
                    .append('\n')
            }
            for (p in prefixes) {
                append("prefix ")
                    .append(p.ifname)
                    .append(' ')
                    .append(p.addrHex)
                    .append(' ')
                    .append(hex(p.prefixLen))
                    .append('\n')
            }
        }

    // ── stats (§4.3) ──────────────────────────────────────────────────────

    fun parseStats(text: String): List<StatEntry>? {
        val h = parseHeader(text) ?: return null
        if (h.kind != Kind.STATS) return null
        val out = mutableListOf<StatEntry>()
        forEachRecord(h.records) { toks ->
            val uid = toks.getOrNull(0)?.let { parseHex(it, 32) }
            if (uid != null) {
                for (j in 1 until toks.size) {
                    val pair = toks[j].split(':')
                    val hid = pair.getOrNull(0)?.let { parseHex(it, 32) }
                    val cnt = pair.getOrNull(1)?.let { parseHex(it, 64) }
                    if (pair.size == 2 && hid != null && cnt != null) {
                        out += StatEntry(uid, hid, cnt)
                    }
                }
            }
        }
        return out
    }

    fun formatStats(entries: List<StatEntry>): String =
        buildString {
            append("vpnhide ").append(VERSION).append(" stats\n")
            var i = 0
            while (i < entries.size) {
                val uid = entries[i].uid
                append(hex(uid))
                while (i < entries.size && entries[i].uid == uid) {
                    append(' ').append(hex(entries[i].hookId)).append(':').append(hex(entries[i].count))
                    i++
                }
                append('\n')
            }
        }

    // ── status (§4.3) ─────────────────────────────────────────────────────

    fun parseStatus(text: String): Status? {
        val h = parseHeader(text) ?: return null
        if (h.kind != Kind.STATUS) return null
        var backend = 0L
        var kver = 0L
        var hooks = 0L
        var error = 0L
        forEachRecord(h.records) { toks ->
            val v = toks.getOrNull(1)?.let { parseHex(it, 32) }
            if (v != null) {
                when (toks.getOrNull(0)) {
                    "backend" -> backend = v
                    "kver" -> kver = v
                    "hooks" -> hooks = v
                    "error" -> error = v
                }
            }
        }
        return Status(backend, kver, hooks, error)
    }

    fun formatStatus(s: Status): String =
        "vpnhide $VERSION status\n" +
            "backend ${hex(s.backend)}\nkver ${hex(s.kver)}\nhooks ${hex(s.hooks)}\nerror ${hex(s.error)}\n"

    /**
     * Clamp a fully-serialised snapshot to `outlen` bytes on a line boundary
     * (§7.2). Whole thing fits ⇒ returns its length (ends in `\n`, complete);
     * else the largest run of complete lines minus the trailing `\n` (the
     * missing newline is the truncation signal).
     */
    fun clampToLine(
        buf: String,
        outlen: Int,
    ): Int {
        if (buf.length <= outlen) return buf.length
        var p = outlen
        while (p > 0 && buf[p - 1] != '\n') p--
        return if (p > 0) p - 1 else 0
    }
}
