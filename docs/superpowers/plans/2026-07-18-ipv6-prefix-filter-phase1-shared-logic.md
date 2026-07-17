# IPv6 Prefix Filter — Phase 1: Shared wire/parser + match logic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a global `prefix <ifname> <addr32hex> <plen>` config record and a pure IPv6-prefix match predicate to vpnhide's freestanding parser, with C host tests, Rust parity, and a C↔Rust differential oracle — all host-testable, no device or Docker.

**Architecture:** Extend the single freestanding parser `kmod/shared/vpnhide_logic.h` (shared verbatim by `.ko` and KPM) with new data + helpers, keeping the existing `vpnhide_parse_config()` signature intact via a thin wrapper over a new `vpnhide_parse_config_ex()`. Mirror the record in the Rust `vpnhide-protocol` crate. Parity is held by the language-independent golden vectors in `kmod/shared/protocol_vectors.tsv` plus the `protocol-diff` proptest, exactly as `docs/protocol.md` §8 prescribes.

**Tech Stack:** Freestanding C (gcc host tests, kernel coding style / clang-format), Rust (`vpnhide-protocol` + `proptest`), pipe-delimited TSV golden vectors.

## Global Constraints

- `kmod/shared/vpnhide_logic.h` is **freestanding**: no `#include`, no libc, no kernel headers, no `memmove`/`strlen`. New helpers use plain byte loops only.
- Wire stays **`version 1`**; the `prefix` record is additive and relies on the "unknown keyword → skip line" forward-compat rule (§4.5). Do NOT bump `VPNHIDE_PROTO_VERSION`.
- Wire is **ASCII, shell-safe** (no `"`, `$`, backtick, `\` in payload).
- Address field: **exactly 32 hex chars**, network order; **read liberal on case, write lowercase** (liberal-in/strict-out, §4.4). Not 32 chars or any non-hex char → reject that line.
- Prefix length: `0x`-hex, range **0..128** inclusive; `> 128` → reject that line.
- Interface name: ASCII token, **1..15** chars (`< VPNHIDE_IFNAMSIZ`), else reject that line.
- Prefix rules are **global** (no UID field).
- `#define MAX_PREFIX_RULES 8` (override-guarded, like `VPNHIDE_IFNAMSIZ`).
- Existing callers of `vpnhide_parse_config()` (kernel `ctl_write`, KPM, diff-oracle `config_wrapper.c`) must keep compiling unchanged — hence the wrapper.
- Follow repo conventions (`CLAUDE.md`): C via `scripts/clang-format-c.sh`; Rust via `cargo fmt`; **no changelog fragment** for Phase 1 (test/internal plumbing, no user-visible behavior yet — added in a later phase); no AI-tool mentions in commit messages.

## Execution environment

Phase 1 needs a **host C compiler** (`gcc`/`clang`) and a **Rust toolchain** (`cargo`, with `cc` crate deps). Neither is confirmed on the Windows host (cargo absent). Run the commands below in **WSL/Linux** or lean on **fork CI** (which already gates the C host vectors + Rust tests + the C↔Rust proptest per `docs/protocol.md` §8). All paths in commands are repo-root-relative; run from the repo root unless a step says otherwise.

## File Structure

- Modify `kmod/shared/vpnhide_logic.h` — add `MAX_PREFIX_RULES`, `struct vpnhide_prefix_rule`, `vpnhide_hexval`, `vpnhide_tok_addr32`, `vpnhide_tok_ifname`, `vpnhide_prefix_match`, `vpnhide_parse_config_ex`, and the `vpnhide_parse_config` wrapper.
- Modify `kmod/shared/test_vpnhide_logic.c` — add `test_prefix_match()` (pure predicate unit test).
- Modify `kmod/shared/test_protocol.c` — switch `run_cfg` to `vpnhide_parse_config_ex` and render parsed prefix rules into the comparison string.
- Modify `kmod/shared/protocol_vectors.tsv` — add `prefix` golden vectors.
- Modify `crates/protocol/src/lib.rs` — add `PrefixRule`, `Config.prefixes`, parse arm, `parse_ifname`/`parse_addr32`/`hexval` helpers, `format_config_ex` (+ keep `format_config` wrapper), and extend the test `run_cfg` renderer.
- Modify `crates/protocol-diff/c/config_wrapper.c` — export `vpnhide_diff_parse_config_ex`.
- Modify `crates/protocol-diff/src/lib.rs` — capture prefixes from C and compare full `Config` (incl. prefixes) in the proptest.

---

### Task 1: Shared data model + pure match/token helpers

**Files:**
- Modify: `kmod/shared/vpnhide_logic.h`
- Test: `kmod/shared/test_vpnhide_logic.c`

**Interfaces:**
- Produces:
  - `#define MAX_PREFIX_RULES 8`
  - `struct vpnhide_prefix_rule { char ifname[VPNHIDE_IFNAMSIZ]; unsigned char addr[16]; unsigned char prefix_len; };`
  - `int vpnhide_hexval(char c)` → `0..15` or `-1`
  - `int vpnhide_tok_addr32(const char *b, unsigned long ts, unsigned long te, unsigned char out[16])` → 1 on success
  - `int vpnhide_tok_ifname(const char *b, unsigned long ts, unsigned long te, char *dst)` → 1 on success
  - `int vpnhide_prefix_match(const unsigned char addr[16], const struct vpnhide_prefix_rule *r)` → 1 if `addr` is within `r`

- [ ] **Step 1: Add the failing unit test** in `kmod/shared/test_vpnhide_logic.c`

Add this function above `main`:

```c
static void test_prefix_match(void)
{
	struct vpnhide_prefix_rule r;
	unsigned char a[16];

	/* 2401:4900::/32 */
	memset(&r, 0, sizeof(r));
	r.prefix_len = 32;
	r.addr[0] = 0x24;
	r.addr[1] = 0x01;
	r.addr[2] = 0x49;
	r.addr[3] = 0x00;

	memset(a, 0, sizeof(a));
	a[0] = 0x24;
	a[1] = 0x01;
	a[2] = 0x49;
	a[3] = 0x00;
	a[4] = 0xa3;
	a[5] = 0xf1; /* 2401:4900:a3f1:: — in-prefix */
	expect_int("prefix /32 in", vpnhide_prefix_match(a, &r), 1);

	a[3] = 0x01; /* 2401:4901:: — out at /32 */
	expect_int("prefix /32 out", vpnhide_prefix_match(a, &r), 0);

	r.prefix_len = 0; /* /0 matches anything */
	expect_int("prefix /0 any", vpnhide_prefix_match(a, &r), 1);

	/* /33: bit 33 must match (byte 4, top bit) */
	memset(&r, 0, sizeof(r));
	r.prefix_len = 33;
	r.addr[4] = 0x80;
	memset(a, 0, sizeof(a));
	a[4] = 0x80;
	expect_int("prefix /33 in", vpnhide_prefix_match(a, &r), 1);
	a[4] = 0x00;
	expect_int("prefix /33 out", vpnhide_prefix_match(a, &r), 0);

	/* /128 exact */
	memset(&r, 0, sizeof(r));
	r.prefix_len = 128;
	r.addr[15] = 0x01;
	memset(a, 0, sizeof(a));
	a[15] = 0x01;
	expect_int("prefix /128 eq", vpnhide_prefix_match(a, &r), 1);
	a[15] = 0x02;
	expect_int("prefix /128 ne", vpnhide_prefix_match(a, &r), 0);

	/* out-of-range plen rejects */
	r.prefix_len = 129;
	expect_int("prefix /129 reject", vpnhide_prefix_match(a, &r), 0);
}
```

Register it in `main` (add before the `if (failures)` block):

```c
	test_prefix_match();
```

- [ ] **Step 2: Run the test to verify it fails to compile**

Run (from `kmod/shared/`):
```
gcc -O2 -Wall -Wextra -Werror -I.. -o /tmp/test_vpnhide_logic test_vpnhide_logic.c
```
Expected: FAIL — `error: unknown type name 'vpnhide_prefix_rule'` / `implicit declaration of 'vpnhide_prefix_match'`.

- [ ] **Step 3: Add the data model + helpers to `kmod/shared/vpnhide_logic.h`**

Add the struct immediately after the existing `struct vpnhide_target { ... };`:

```c
#ifndef MAX_PREFIX_RULES
#define MAX_PREFIX_RULES 8
#endif

/* one `prefix <ifname> <addr32hex> <plen>` config record (global scope): hide
 * any v6 on interface `ifname` whose first `prefix_len` bits equal `addr`. */
struct vpnhide_prefix_rule {
	char ifname[VPNHIDE_IFNAMSIZ]; /* NUL-terminated */
	unsigned char addr[16];        /* network order  */
	unsigned char prefix_len;      /* 0..128         */
};
```

Add the helpers immediately after `vpnhide_tok_hex(...)`:

```c
/* Single hex digit → 0..15, else -1. Case-insensitive (§4.4 liberal-in). */
static inline int vpnhide_hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/*
 * Parse EXACTLY 32 hex chars [ts,te) into out[16] (network order). A 128-bit
 * IPv6 address does not fit the 0x-hex u32/u64 primitive (§4.4), so the prefix
 * record uses the fixed-width bare-hex spelling /proc/net/if_inet6 already
 * uses. Not 32 chars, or any non-hex char → 0 (reject the line).
 */
static inline int vpnhide_tok_addr32(const char *b, unsigned long ts,
				     unsigned long te, unsigned char out[16])
{
	int i, hi, lo;

	if (te - ts != 32)
		return 0;
	for (i = 0; i < 16; i++) {
		hi = vpnhide_hexval(b[ts + (unsigned long)(2 * i)]);
		lo = vpnhide_hexval(b[ts + (unsigned long)(2 * i + 1)]);
		if (hi < 0 || lo < 0)
			return 0;
		out[i] = (unsigned char)((hi << 4) | lo);
	}
	return 1;
}

/*
 * Copy an interface-name token [ts,te) into dst[VPNHIDE_IFNAMSIZ]. Empty, or
 * too long to hold a NUL (>= IFNAMSIZ) → 0 (reject the line).
 */
static inline int vpnhide_tok_ifname(const char *b, unsigned long ts,
				     unsigned long te, char *dst)
{
	unsigned long n = te - ts, j;

	if (n == 0 || n >= (unsigned long)VPNHIDE_IFNAMSIZ)
		return 0;
	for (j = 0; j < n; j++)
		dst[j] = b[ts + j];
	dst[n] = '\0';
	return 1;
}

/*
 * True if the first `r->prefix_len` bits of `addr` equal `r->addr`. Bits beyond
 * the prefix are ignored; the boundary byte is masked. prefix_len > 128 → 0.
 */
static inline int vpnhide_prefix_match(const unsigned char addr[16],
				       const struct vpnhide_prefix_rule *r)
{
	unsigned int full, rem, i;

	if (!addr || !r || r->prefix_len > 128)
		return 0;
	full = (unsigned int)r->prefix_len >> 3;
	rem = (unsigned int)r->prefix_len & 7u;
	for (i = 0; i < full; i++)
		if (addr[i] != r->addr[i])
			return 0;
	if (rem) {
		unsigned char mask = (unsigned char)(0xffu << (8u - rem));

		if (((addr[full] ^ r->addr[full]) & mask) != 0)
			return 0;
	}
	return 1;
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run (from `kmod/shared/`):
```
gcc -O2 -Wall -Wextra -Werror -I.. -o /tmp/test_vpnhide_logic test_vpnhide_logic.c && /tmp/test_vpnhide_logic
```
Expected: PASS — `all shared-logic tests passed`, exit 0.

- [ ] **Step 5: Format and commit**

```bash
./scripts/clang-format-c.sh
git add kmod/shared/vpnhide_logic.h kmod/shared/test_vpnhide_logic.c
git commit -m "kmod: add IPv6 prefix rule data model and match predicate"
```

---

### Task 2: Parser support for the `prefix` record + golden vectors

**Files:**
- Modify: `kmod/shared/vpnhide_logic.h`
- Modify: `kmod/shared/test_protocol.c`
- Modify: `kmod/shared/protocol_vectors.tsv`

**Interfaces:**
- Consumes: `struct vpnhide_prefix_rule`, `vpnhide_tok_addr32`, `vpnhide_tok_ifname`, `vpnhide_prefix_match` (Task 1).
- Produces:
  - `int vpnhide_parse_config_ex(const char *b, unsigned long len, struct vpnhide_target *out, int max, int *debug, struct vpnhide_prefix_rule *pout, int pmax, int *pnr)` — returns target count (or −1 reject); fills `pout[0..*pnr)` when `pout`/`pnr` non-NULL.
  - `vpnhide_parse_config(...)` unchanged 5-arg signature (now a wrapper).
  - Golden-vector rendering of a parsed prefix: `;pfx:<ifname>:<32hexlower>:<plen decimal>` appended after target cells.

- [ ] **Step 1: Add the failing vectors** to `kmod/shared/protocol_vectors.tsv`

Append this block at the end of the file:

```
# --- prefix rules (IPv6 prefix filter) -------------------------------------
# a single global prefix rule parses; rendered as ;pfx:<iface>:<32hex>:<plen>
cfg|vpnhide 1 config\nprefix rmnet_data1 24014900000000000000000000000000 0x20\n|debug=-1;pfx:rmnet_data1:24014900000000000000000000000000:32
# targets first (return count), then prefixes
cfg|vpnhide 1 config\ntarget 0x2710 0x1\nprefix wlan0 fe800000000000000000000000000000 0x40\n|debug=-1;0x2710:0x1;pfx:wlan0:fe800000000000000000000000000000:64
# address is liberal-in on case; rendered lowercase-out
cfg|vpnhide 1 config\nprefix eth0 2401490000000000000000000000ABCD 0x80\n|debug=-1;pfx:eth0:2401490000000000000000000000abcd:128
# short address (31 chars) -> reject that line
cfg|vpnhide 1 config\nprefix rmnet_data1 2401490000000000000000000000000 0x20\ntarget 0x5 0x2\n|debug=-1;0x5:0x2
# long address (33 chars) -> reject that line
cfg|vpnhide 1 config\nprefix rmnet_data1 240149000000000000000000000000000 0x20\ntarget 0x6 0x2\n|debug=-1;0x6:0x2
# plen > 128 -> reject that line
cfg|vpnhide 1 config\nprefix rmnet_data1 24014900000000000000000000000000 0x81\n|debug=-1
# overlong ifname (16 chars) -> reject that line
cfg|vpnhide 1 config\nprefix abcdefghijklmnop 24014900000000000000000000000000 0x20\n|debug=-1
# missing plen token -> reject that line
cfg|vpnhide 1 config\nprefix rmnet_data1 24014900000000000000000000000000\n|debug=-1
```

- [ ] **Step 2: Teach the harness to render prefixes** in `kmod/shared/test_protocol.c`

Replace the body of `run_cfg` (the `parse_config` call + the "Build ... and compare" section) with:

```c
static void run_cfg(const char *raw_in, const char *expect)
{
	char in[2048];
	unsigned long len = decode(raw_in, in, sizeof(in));
	struct vpnhide_target out[MAX_TARGETS];
	struct vpnhide_prefix_rule pr[MAX_PREFIX_RULES];
	int debug = -1;
	int npr = 0;
	int n = vpnhide_parse_config_ex(in, len, out, MAX_TARGETS, &debug, pr,
					MAX_PREFIX_RULES, &npr);

	checks++;
	if (strcmp(expect, "REJECT") == 0) {
		if (n != -1)
			fail("cfg expected REJECT", "accepted", "REJECT");
		return;
	}
	if (n < 0) {
		fail("cfg unexpectedly rejected", "REJECT", expect);
		return;
	}

	/* "debug=<d>;uid:hm;...;pfx:iface:32hex:plen;..." */
	char got[2048];
	int pos = snprintf(got, sizeof(got), "debug=%d", debug);
	for (int i = 0; i < n; i++)
		pos += snprintf(got + pos, sizeof(got) - (size_t)pos,
				";0x%x:0x%x", out[i].uid, out[i].hookmask);
	for (int i = 0; i < npr; i++) {
		pos += snprintf(got + pos, sizeof(got) - (size_t)pos,
				";pfx:%s:", pr[i].ifname);
		for (int j = 0; j < 16; j++)
			pos += snprintf(got + pos, sizeof(got) - (size_t)pos,
					"%02x", pr[i].addr[j]);
		pos += snprintf(got + pos, sizeof(got) - (size_t)pos, ":%u",
				pr[i].prefix_len);
	}
	if (strcmp(got, expect) != 0)
		fail("cfg parse mismatch", got, expect);
}
```

- [ ] **Step 3: Run to verify it fails**

Run (from `kmod/shared/`):
```
gcc -O2 -Wall -Wextra -Werror -I.. -o /tmp/test_protocol test_protocol.c
```
Expected: FAIL — `implicit declaration of function 'vpnhide_parse_config_ex'`.

- [ ] **Step 4: Add `vpnhide_parse_config_ex` + wrapper** in `kmod/shared/vpnhide_logic.h`

Replace the existing `vpnhide_parse_config(...)` definition with the following (renamed body with prefix out-params + a back-compat wrapper). The `debug` and `target` arms are unchanged from the original; only the `prefix` arm and the signature/`*pnr` init are new:

```c
static inline int vpnhide_parse_config_ex(const char *b, unsigned long len,
					  struct vpnhide_target *out, int max,
					  int *debug,
					  struct vpnhide_prefix_rule *pout,
					  int pmax, int *pnr)
{
	unsigned long i, ls, le, cs, p, ts, te;
	int ascii, n = 0;
	enum vpnhide_kind k = vpnhide_parse_header(b, len, &i);

	if (pnr)
		*pnr = 0;
	if (k != VPNHIDE_KIND_CONFIG)
		return -1;

	while (vpnhide_next_line(b, len, &i, &ls, &le)) {
		if (!vpnhide_line_significant(b, ls, le, &cs, &ascii) || !ascii)
			continue;
		p = cs;
		if (!vpnhide_next_token(b, &p, le, &ts, &te))
			continue;
		if (vpnhide_tok_eq(b, ts, te, "debug")) {
			if (!vpnhide_next_token(b, &p, le, &ts, &te))
				continue;
			if (vpnhide_tok_eq(b, ts, te, "0")) {
				if (debug)
					*debug = 0;
			} else if (vpnhide_tok_eq(b, ts, te, "1")) {
				if (debug)
					*debug = 1;
			}
			/* any other flag value ⇒ malformed, skip */
		} else if (vpnhide_tok_eq(b, ts, te, "target")) {
			unsigned long long uid, hm;

			if (!vpnhide_next_token(b, &p, le, &ts, &te) ||
			    !vpnhide_tok_hex(b, ts, te, 32, &uid))
				continue;
			if (!vpnhide_next_token(b, &p, le, &ts, &te) ||
			    !vpnhide_tok_hex(b, ts, te, 32, &hm))
				continue;
			vpnhide_target_set(out, &n, max, (unsigned int)uid,
					   (unsigned int)hm);
		} else if (vpnhide_tok_eq(b, ts, te, "prefix")) {
			struct vpnhide_prefix_rule r;
			unsigned long long plen;

			if (!vpnhide_next_token(b, &p, le, &ts, &te) ||
			    !vpnhide_tok_ifname(b, ts, te, r.ifname))
				continue;
			if (!vpnhide_next_token(b, &p, le, &ts, &te) ||
			    !vpnhide_tok_addr32(b, ts, te, r.addr))
				continue;
			if (!vpnhide_next_token(b, &p, le, &ts, &te) ||
			    !vpnhide_tok_hex(b, ts, te, 32, &plen) ||
			    plen > 128)
				continue;
			r.prefix_len = (unsigned char)plen;
			if (pout && pnr && *pnr < pmax)
				pout[(*pnr)++] = r;
		}
		/* unknown first token ⇒ skip the line (§4.5) */
	}
	return n;
}

/* Back-compat wrapper: targets + debug only (existing callers unchanged). */
static inline int vpnhide_parse_config(const char *b, unsigned long len,
				       struct vpnhide_target *out, int max,
				       int *debug)
{
	return vpnhide_parse_config_ex(b, len, out, max, debug, 0, 0, 0);
}
```

- [ ] **Step 5: Run to verify all vectors pass**

Run (from `kmod/shared/`):
```
gcc -O2 -Wall -Wextra -Werror -I.. -o /tmp/test_protocol test_protocol.c && /tmp/test_protocol protocol_vectors.tsv
```
Expected: PASS — `all N protocol vectors passed` (N now includes the 8 new prefix vectors), exit 0.

- [ ] **Step 6: Re-run Task 1's test** (the wrapper must not have regressed anything)

Run (from `kmod/shared/`):
```
gcc -O2 -Wall -Wextra -Werror -I.. -o /tmp/test_vpnhide_logic test_vpnhide_logic.c && /tmp/test_vpnhide_logic
```
Expected: PASS.

- [ ] **Step 7: Format and commit**

```bash
./scripts/clang-format-c.sh
git add kmod/shared/vpnhide_logic.h kmod/shared/test_protocol.c kmod/shared/protocol_vectors.tsv
git commit -m "kmod: parse the prefix config record; pin with golden vectors"
```

---

### Task 3: Rust `vpnhide-protocol` parity

**Files:**
- Modify: `crates/protocol/src/lib.rs`

**Interfaces:**
- Consumes: the shared golden vectors (Task 2) via the existing `golden_vectors` test.
- Produces:
  - `pub struct PrefixRule { pub ifname: String, pub addr: [u8; 16], pub prefix_len: u8 }`
  - `Config { debug, targets, prefixes: Vec<PrefixRule> }`
  - `pub fn format_config_ex(debug: bool, targets: &[Target], prefixes: &[PrefixRule]) -> String` (+ `format_config` wrapper unchanged).

- [ ] **Step 1: Extend the Rust test renderer to expect prefixes** in `crates/protocol/src/lib.rs`

In `mod tests`, in `run_cfg`, replace the `got` construction with:

```rust
        let mut got = format!("debug={dbg}");
        for t in &cfg.targets {
            got.push_str(&format!(";0x{:x}:0x{:x}", t.uid, t.hookmask));
        }
        for pr in &cfg.prefixes {
            got.push_str(&format!(";pfx:{}:", pr.ifname));
            for b in pr.addr {
                got.push_str(&format!("{b:02x}"));
            }
            got.push_str(&format!(":{}", pr.prefix_len));
        }
        assert_eq!(got, expect, "cfg mismatch for {input:?}");
```

- [ ] **Step 2: Run the Rust tests to verify failure**

Run (from repo root):
```
cargo test -p vpnhide-protocol
```
Expected: FAIL — `no field 'prefixes' on type '&Config'` (compile error).

- [ ] **Step 3: Add the Rust data model, helpers, parse arm, and formatter** in `crates/protocol/src/lib.rs`

Add the struct after `struct Target { ... }`:

```rust
/// One `prefix <ifname> <addr32hex> <plen>` record (§4.3, global scope).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrefixRule {
    pub ifname: String,
    pub addr: [u8; 16],
    pub prefix_len: u8,
}
```

Add `prefixes` to `Config`:

```rust
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    pub debug: Option<bool>,
    pub targets: Vec<Target>,
    pub prefixes: Vec<PrefixRule>,
}
```

Add these free functions next to `parse_hex`:

```rust
fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse exactly 32 hex chars (any case) into 16 network-order bytes (§4.3).
fn parse_addr32(tok: &[u8]) -> Option<[u8; 16]> {
    if tok.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hexval(tok[2 * i])?;
        let lo = hexval(tok[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// An interface-name token: 1..15 ASCII chars (tokens are already ASCII, since
/// `significant()` rejects non-ASCII lines). Empty or >= 16 → None.
fn parse_ifname(tok: &[u8]) -> Option<String> {
    if tok.is_empty() || tok.len() >= 16 {
        return None;
    }
    Some(String::from_utf8_lossy(tok).into_owned())
}
```

In `parse_config`, initialise `prefixes` and add the `prefix` match arm:

```rust
    let mut cfg = Config {
        debug: None,
        targets: Vec::new(),
        prefixes: Vec::new(),
    };
```

```rust
            Some(b"prefix") => {
                let (Some(ifname), Some(addr), Some(plen)) = (
                    it.next().and_then(parse_ifname),
                    it.next().and_then(parse_addr32),
                    it.next().and_then(|t| parse_hex(t, 32)),
                ) else {
                    continue; // malformed ⇒ skip line
                };
                if plen > 128 {
                    continue;
                }
                cfg.prefixes.push(PrefixRule {
                    ifname,
                    addr,
                    prefix_len: plen as u8,
                });
            }
```

Replace `format_config` with an `_ex` form + wrapper:

```rust
/// Serialise a `config` snapshot with prefix rules (lowercase-out, §4.4).
pub fn format_config_ex(debug: bool, targets: &[Target], prefixes: &[PrefixRule]) -> String {
    let mut out = String::from("vpnhide 1 config\n");
    out.push_str(if debug { "debug 1\n" } else { "debug 0\n" });
    for t in targets {
        out.push_str(&format!("target 0x{:x} 0x{:x}\n", t.uid, t.hookmask));
    }
    for pr in prefixes {
        out.push_str(&format!("prefix {} ", pr.ifname));
        for b in pr.addr {
            out.push_str(&format!("{b:02x}"));
        }
        out.push_str(&format!(" 0x{:x}\n", pr.prefix_len));
    }
    out
}

/// Serialise a `config` snapshot (targets only). Existing callers unchanged.
pub fn format_config(debug: bool, targets: &[Target]) -> String {
    format_config_ex(debug, targets, &[])
}
```

- [ ] **Step 4: Run the Rust tests to verify pass**

Run (from repo root):
```
cargo test -p vpnhide-protocol
```
Expected: PASS — `golden_vectors` and `formats_config_snapshot` green (the `assert!(count >= 30 ...)` still holds; the count grew).

- [ ] **Step 5: Format, lint, and commit**

```bash
cargo fmt -p vpnhide-protocol
cargo clippy -p vpnhide-protocol -- -D warnings
git add crates/protocol/src/lib.rs
git commit -m "protocol: mirror the prefix record in the Rust parser"
```

---

### Task 4: C↔Rust differential oracle covers prefixes

**Files:**
- Modify: `crates/protocol-diff/c/config_wrapper.c`
- Modify: `crates/protocol-diff/src/lib.rs`

**Interfaces:**
- Consumes: `vpnhide_parse_config_ex` (Task 2), `Config.prefixes`/`PrefixRule` (Task 3).
- Produces: `int vpnhide_diff_parse_config_ex(const unsigned char*, unsigned long, struct vpnhide_target*, int, int*, struct vpnhide_prefix_rule*, int, int*)` and a proptest asserting C and Rust agree on the **full** `Config` (targets + debug + prefixes).

- [ ] **Step 1: Export the extended parser from the C wrapper** — append to `crates/protocol-diff/c/config_wrapper.c`:

```c
/* Extended wrapper: also surfaces parsed prefix rules for the diff oracle. */
int vpnhide_diff_parse_config_ex(const unsigned char *input, unsigned long len,
                                 struct vpnhide_target *targets, int capacity,
                                 int *debug,
                                 struct vpnhide_prefix_rule *prefixes,
                                 int pcapacity, int *pcount)
{
    return vpnhide_parse_config_ex((const char *)input, len, targets, capacity,
                                   debug, prefixes, pcapacity, pcount);
}
```

- [ ] **Step 2: Extend the proptest to capture + compare prefixes** in `crates/protocol-diff/src/lib.rs`

Replace the `use` line, add the C prefix struct + extern, and rebuild `parse_with_c`:

```rust
    use proptest::prelude::*;
    use vpnhide_protocol::{Config, PrefixRule, Target, parse_config};

    const C_TARGET_CAPACITY: usize = 128;
    const C_PREFIX_CAPACITY: usize = 32;

    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    struct CTarget {
        uid: u32,
        hookmask: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct CPrefixRule {
        ifname: [u8; 16],
        addr: [u8; 16],
        prefix_len: u8,
    }

    impl Default for CPrefixRule {
        fn default() -> Self {
            Self { ifname: [0; 16], addr: [0; 16], prefix_len: 0 }
        }
    }

    unsafe extern "C" {
        fn vpnhide_diff_parse_config_ex(
            input: *const u8,
            len: usize,
            targets: *mut CTarget,
            capacity: i32,
            debug: *mut i32,
            prefixes: *mut CPrefixRule,
            pcapacity: i32,
            pcount: *mut i32,
        ) -> i32;
    }

    fn parse_with_c(input: &[u8]) -> Option<Config> {
        let mut targets = [CTarget::default(); C_TARGET_CAPACITY];
        let mut prefixes = [CPrefixRule::default(); C_PREFIX_CAPACITY];
        let mut debug = -1;
        let mut pcount = 0;
        let count = unsafe {
            vpnhide_diff_parse_config_ex(
                input.as_ptr(),
                input.len(),
                targets.as_mut_ptr(),
                C_TARGET_CAPACITY as i32,
                &mut debug,
                prefixes.as_mut_ptr(),
                C_PREFIX_CAPACITY as i32,
                &mut pcount,
            )
        };
        if count < 0 {
            return None;
        }
        Some(Config {
            debug: match debug {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            },
            targets: targets[..count as usize]
                .iter()
                .map(|t| Target { uid: t.uid, hookmask: t.hookmask })
                .collect(),
            prefixes: prefixes[..pcount as usize]
                .iter()
                .map(|p| {
                    let end = p.ifname.iter().position(|&b| b == 0).unwrap_or(16);
                    PrefixRule {
                        ifname: String::from_utf8_lossy(&p.ifname[..end]).into_owned(),
                        addr: p.addr,
                        prefix_len: p.prefix_len,
                    }
                })
                .collect(),
        })
    }
```

The `proptest!` block is unchanged — it already asserts `parse_with_c(&input) == parse_config(&input)`, and `Config`'s derived `PartialEq` now covers `prefixes`.

- [ ] **Step 3: Run the differential oracle**

Run (from repo root):
```
cargo test -p vpnhide-protocol-diff
```
Expected: PASS — `c_and_rust_config_parsers_agree` runs 2048 proptest cases with no divergence. (Note: the C oracle capacity is 128 targets; Rust `parse_config` has no cap, so the existing tests avoid >128-target inputs — the prefix arm adds no new cap mismatch since both sides accept the same lines.)

- [ ] **Step 4: Guard the target-capacity edge for prefixes** — add a focused regression proptest under the existing one in `crates/protocol-diff/src/lib.rs`:

```rust
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Bias inputs toward well-formed prefix lines so the oracle exercises
        /// the new arm densely, not just via random bytes.
        #[test]
        fn c_and_rust_agree_on_prefix_lines(
            iface in "[a-z]{1,15}",
            addr in "[0-9a-fA-F]{32}",
            plen in 0u16..=140,
        ) {
            let payload = format!("vpnhide 1 config\nprefix {iface} {addr} 0x{plen:x}\n");
            prop_assert_eq!(
                parse_with_c(payload.as_bytes()),
                parse_config(payload.as_bytes())
            );
        }
    }
```

- [ ] **Step 5: Run again**

Run (from repo root):
```
cargo test -p vpnhide-protocol-diff
```
Expected: PASS — both proptests green.

- [ ] **Step 6: Format and commit**

```bash
cargo fmt -p vpnhide-protocol-diff
git add crates/protocol-diff/c/config_wrapper.c crates/protocol-diff/src/lib.rs
git commit -m "protocol-diff: extend the C↔Rust oracle to prefix rules"
```

---

## Self-Review

**1. Spec coverage (Phase 1 slice of the design spec §5, §6, §8):**
- §5 wire record grammar (`prefix <ifname> <addr32hex> <plen>`, 32-hex, plen 0..128, global) → Task 2 parser + vectors. ✅
- §6 shared structs + `vpnhide_tok_addr32`/`vpnhide_tok_ifname`/`vpnhide_prefix_match` + `vpnhide_parse_config` extension (non-breaking wrapper) → Tasks 1-2. ✅
- §8 Rust parity + golden vectors + Rust↔C diff oracle → Tasks 3-4. ✅
- Out of Phase 1 (later plans): `if6_seq_show` compaction + hook, kernel state/apply, codegen hook id, activator JSON, KPM/Zygisk, LSPosed UI, on-device verification. Explicitly deferred — not gaps.

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code; every run step shows the exact command + expected result. ✅

**3. Type consistency:** `vpnhide_parse_config_ex` signature identical across the header (Task 2), C wrapper (Task 4), and Rust extern (Task 4: `vpnhide_diff_parse_config_ex`). `PrefixRule { ifname: String, addr: [u8;16], prefix_len: u8 }` identical in Task 3 and Task 4. Golden-vector rendering `;pfx:<ifname>:<32hexlower>:<plen decimal>` identical in the C harness (Task 2) and Rust harness (Task 3). `CPrefixRule` field order/types match the C struct `{ char ifname[16]; unsigned char addr[16]; unsigned char prefix_len; }`. ✅

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-18-ipv6-prefix-filter-phase1-shared-logic.md`.
