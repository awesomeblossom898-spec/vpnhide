# IPv6 Prefix Filter — Phase 6: Zygisk Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add global IPv6 prefix-rule filtering to the Zygisk (Rust libc-hook) backend — `getifaddrs`, `openat` (`/proc/net/if_inet6` + `/proc/net/ipv6_route`), and the netlink dump path (`recv`/`recvfrom`/`__recvfrom_chk`/`recvmsg`, scatter/gather-safe) — with full host-test coverage, a fork CI gate, and on-device acceptance via ReZygisk + an in-target-app probe on the Nord 3.

**Architecture:** The wire `prefix` record (v1, Phase 1) already reaches the Zygisk backend: the activator's `zygisk` bin projects `ipv6PrefixRules` from the canonical JSON into `targets.txt` (`project_native_with_resolver_for_family` → `project_prefix_rules` → `format_config_ex`, `crates/activator/src/model.rs:372-434,397`), and `vpnhide_protocol::parse_config` already parses them into `Config.prefixes` (`crates/protocol/src/lib.rs:316-332,64`). The module's `load_config_from_dir_fd` currently drops them (`zygisk/src/lib.rs:206-227`) — the "parse-and-ignore" starting point. Phase 6 carries the rules into `ZygiskConfig`, exposes them to the hook layer, and adds prefix matching to the three Zygisk hook surfaces, mirroring the kernel semantics bit-for-bit (C reference: `vpnhide_prefix_match` + `vpnhide_compact_if_inet6_lines` in `kmod/shared/vpnhide_logic.h`).

**Tech Stack:** Rust 2024 (cdylib via cargo-ndk, host-testable), ByteDance shadowhook inline hooks, GitHub Actions (fork CI), ReZygisk on-device, Termux RUN_COMMAND intents as the in-app probe harness.

---

## Verified facts (recon 2026-07-19 — trust these; re-verified against HEAD `0222cd5`)

1. `zygisk/src/lib.rs:172-177` — `ZygiskConfig { targets, debug }`; `CACHED_CONFIG: OnceLock` set in `on_load` per app launch; hooks read config only via `target_hookmask` at specialize time.
2. `zygisk/src/lib.rs:206-227` — `load_config_from_dir_fd` calls `protocol::parse_config`, keeps `targets` (masked by `ZYGISK_HOOK_MASK = 0x1fc0000`) + `debug`, **drops `cfg.prefixes`**.
3. `crates/protocol/src/lib.rs:51-56` — `PrefixRule { ifname: String, addr: [u8;16], prefix_len: u8 }`; `MAX_PREFIX_RULES = 8` (:34); parser caps plen at 128 (:324).
4. `crates/activator/src/model.rs:372-434` — prefix rules project to **every** native family incl. `NativeHookFamily::Zygisk`; `lib.rs:125-128` writes them to `/data/adb/modules/vpnhide_zygisk/targets.txt`. **No activator work needed.**
5. `docs/protocol.md:455` — Zygisk channel: config `debug`,`target`; stats "no, not yet (§7)"; status via app heartbeat. **Zygisk has NO stats channel → Phase 6 has NO stats work** (no sentinel-uid row; that was kernel/KPM-only).
6. **Uid gate is structural in Zygisk:** hooks install only inside target-app processes (`pre_app_specialize`, mask ≠ 0; `lib.rs:259-283`); target uids are app uids ≥ 10000 = exactly the kernel's `vpnhide_uid_prefix_filtered` pass set; `system_server` is never hooked (no `pre_server_specialize` override, `lib.rs:310-311`). No in-process uid check is needed — document this equivalence in code comments.
7. "Enabled" semantics ride for free: each hook installs only when its bit is set for the target uid (`install_hooks`, `lib.rs:375-466`), so prefix filtering inside a hook is per-hook-enabled by construction.
8. Hook surfaces (`zygisk/src/hooks.rs`): `hooked_getifaddrs` (:324-366, unlink loop with `slot` cursor); `hooked_openat` (:547-576) → `open_filtered_proc_net` → `apply_filter` (:677-702) with `ProcNetFile::{Ipv6Route, IfInet6, …}`; netlink entry point `maybe_filter_netlink_buf` (:973-1013) shared by `hooked_recv`/`hooked_recvfrom`/`hooked_recvfrom_chk`, and the scatter/gather path in `hooked_recvmsg` (:814-873) via `rewrite_iovec_payload` (:906-960).
9. `zygisk/src/filter.rs`: `compact_lines` (:39), `filter_by_last_field` (:135-140) shared by `filter_ipv6_route_buf`/`filter_if_inet6_buf`; `extract_last_field` (:144-154); `filter_netlink_dump` (:313-372) drops `RTM_NEWLINK`/`RTM_NEWADDR` (ifindex at payload+4) and `RTM_NEWROUTE` (via `route_oif`, :269-285, `RTA_OIF=4`); `NLMSG_HDRLEN=16`, `RTMSG_HDRLEN=12`; host tests at :374-678; iovec scatter/gather test at `hooks.rs:1183-1249`.
10. C parity target: `vpnhide_prefix_match` (`kmod/shared/vpnhide_logic.h:584-603`) — full bytes then a `0xff << (8-rem)` top-bit mask on the boundary byte; plen 0 matches all; plen > 128 never matches. Route semantics: DESTINATION only, route plen NEVER consulted; a missing `RTA_DST` means `::/0` = all-zero addr (kernel `rt6key.addr` parity — a plen-0 rule covers it).
11. `/proc/net/if_inet6` line: `<addr32hex> <idx8hex> <plen2hex> <scope2hex> <flags2hex> <ifname>` — addr FIRST field, iface LAST field. `/proc/net/ipv6_route` line: dst addr FIRST field (32 hex), iface LAST field. No header lines in either file.
12. Netlink v6 layouts: `ifaddrmsg` = family(1) plen(1) flags(1) scope(1) index(4) = 8 B, rtattrs follow; `IFA_ADDRESS=1`, `IFA_LOCAL=2` (kernel fills `IFA_LOCAL` with `ifa->addr` — kernel parity = match `IFA_LOCAL`, fall back to `IFA_ADDRESS`); `rtmsg` = 12 B, family at +0; `RTA_DST=1` (16 B for v6), `RTA_OIF=4`. `AF_INET6 = 10`.
13. CI today: `.github/workflows/prefix-phase1-check.yml` rust job runs fmt/clippy/test for `-p vpnhide_protocol -p vpnhide_protocol_diff -p vpnhide_activator` — **NOT `vpnhide_zygisk`** (fork gap). Stock `ci.yml:111,115` proves host `cargo test -p vpnhide_zygisk` + `cargo ndk clippy -p vpnhide_zygisk` work on ubuntu runners. `zygisk/build.rs` skips the shadowhook cmake build for non-android targets (:23-28) so host test needs no NDK/submodules.
14. `zygisk/build.py` builds cdylib + activator and zips `zygisk/target/vpnhide-zygisk.zip` (stock `ci.yml:477-483` uploads it as artifact `vpnhide-zygisk`); needs `submodules: recursive` (shadowhook), NDK, cmake.
15. Device (Nord 3, d78a88ef): ReZygisk v1.0.0 (518) installed+enabled; **`/data/adb/modules/vpnhide_zygisk/` does NOT exist** (module never installed); Termux NOT installed; `vpnhide_kmod` healthy with the 8-rule blanket on the kernel channel (separate from the Zygisk channel — no conflict).
16. `zygisk/module/service.sh` runs the module's `activator --boot-wait` at boot → rewrites `targets.txt` from the canonical JSON. On-device test flow = write test canonical JSON → run module activator manually → it writes `targets.txt` (end-to-end, the real user flow).
17. `if_nametoindex` under the `IN_GETIFADDRS` thread-local guard passes through our ioctl hook (`hooks.rs:1165-1171` precedent in `collect_vpn_iface_indices`).
18. `rewrite_iovec_payload` (:906-960) is filter-agnostic (takes a closure) — scatter/gather safety reduces to passing a prefix-aware closure; existing boundary-crossing test must keep passing.
19. Local Windows box: no working host cargo for zygisk (zygisk-api git dep has NTFS-reserved `src/aux.rs`) — **fork CI is the first compile gate** (HARD CONTRACT, same as KPM: implementers edit+commit only, orchestrator gates via CI). Local Android SDK+NDK exists for building the on-device probe binary.
20. `kmod/test/gai-probe.c` is the established getifaddrs probe (spec §13/§14 acceptance row) — build it for aarch64 with the local NDK clang, run INSIDE the target app via Termux RUN_COMMAND for the getifaddrs acceptance row.

## Scope boundary

- **In:** `zygisk/src/{lib.rs,filter.rs,hooks.rs}`; fork CI workflows; `docs/detection-vectors.md`, `docs/diagnostics.md`, `docs/protocol.md`; on-device acceptance. Host unit tests for every new pure filter.
- **Out:** activator changes (none needed — fact 4); stats (none exist — fact 5); LSPosed/Java (Phase 7); `/proc/net/tcp6` prefix filtering (kernel doesn't do it either — parity); `SIOCGIFCONF` (v4-only on Linux — no v6 to prefix-filter); `RTM_GETROUTE single` (`ip route get` — intentionally unhooked everywhere); changelog fragment (unreleased-feature extension, same rule as Phases 2-5); VERSION/release.
- **Hard constraints:** do NOT filter IPv4 (family byte gate on every netlink prefix path); do NOT touch `data/interfaces.toml` / generated files; scatter/gather must stay safe (fact 18); no `#NN`; no AI mentions; hooks stay reentrant-safe — no locks, allocation only on the already-allocating slow paths.

---

### Task 0: fork CI gates — zygisk rust checks + module-zip build job

**Files:**
- Modify: `.github/workflows/prefix-phase1-check.yml` (rust job: add `-p vpnhide_zygisk` to the fmt, clippy, and test commands — lines with `cargo fmt --check`, `cargo clippy`, `cargo test`).
- Modify: `.github/workflows/prefix-kmod-build.yml` (add a `zygisk:` job mirroring the existing `kpm:` job shape).

- [ ] **Step 1: phase1-check rust job**

Add `-p vpnhide_zygisk` to all three cargo invocations so they read:

```yaml
      - name: cargo fmt
        run: cargo fmt --check -p vpnhide_protocol -p vpnhide_protocol_diff -p vpnhide_activator -p vpnhide_zygisk
      - name: cargo clippy
        run: cargo clippy -p vpnhide_protocol -p vpnhide_protocol_diff -p vpnhide_activator -p vpnhide_zygisk --all-targets -- -D warnings
      - name: cargo test (protocol + diff oracle + activator + zygisk)
        run: cargo test -p vpnhide_protocol -p vpnhide_protocol_diff -p vpnhide_activator -p vpnhide_zygisk
```

(Adapt to the real step names; the semantic change is the package list. If host clippy on `vpnhide_zygisk` fails for reasons unrelated to our code — zygisk-api host cfg quirks — fall back to keeping host clippy scoped as today and add `cargo ndk -t arm64-v8a clippy -p vpnhide_zygisk --tests -- -D warnings` to the new zygisk job in prefix-kmod-build.yml instead, mirroring stock `ci.yml:110-111`; report which shape was shipped.)

- [ ] **Step 2: zygisk build job in prefix-kmod-build.yml**

Mirror the `kpm:` job (checkout with `submodules: recursive` + `fetch-depth: 0`, safe.directory, rustup target, cargo-ndk, system packages). The zygisk job additionally needs `cmake`+`ninja-build` (build.rs) and runs `cd zygisk && ./build.py`, then uploads the zip:

```yaml
  zygisk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          submodules: recursive
          fetch-depth: 0
      - name: git safe.directory
        run: git config --global --add safe.directory "$GITHUB_WORKSPACE"
      - name: Rust target + cargo-ndk + native tools
        run: |
          rustup target add aarch64-linux-android
          cargo install cargo-ndk --locked
          sudo apt-get update && sudo apt-get install -y clang lld make cmake ninja-build
      - name: Build zygisk module zip
        run: |
          export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_NDK_LATEST_HOME}"
          cd zygisk && ./build.py
      - uses: actions/upload-artifact@v7
        with:
          name: vpnhide-zygisk
          path: zygisk/target/vpnhide-zygisk.zip
          if-no-files-found: error
```

(READ the real `kpm:` job first and preserve any details this transcription gets wrong — exact checkout action version, safe.directory form, apt invocation, artifact action version. The zygisk zip name `vpnhide-zygisk.zip` is fixed by `zygisk/build.py`/`scripts/build_lib.py::make_zip`; verify the path with `ls zygisk/target/` in the job log.)

- [ ] **Step 3: commit + push alone + green gate**

Commit message: `ci: gate + build the zygisk crate on the fork (rust checks, module zip)`. Push to `fork feat/ipv6-prefix-filter`; wait for BOTH workflows green on the push; download nothing yet (artifact gets exercised at T6).

---

### Task 1: prefix-rule core — config plumbing + pure matchers

**Files:**
- Modify: `zygisk/src/lib.rs` (`ZygiskConfig`, `load_config_from_dir_fd`, new `prefix_rules()` accessor, doc comments).
- Modify: `zygisk/src/filter.rs` (new `prefix_match`, `prefix_rule_hit`, `parse_addr32_hex`, `IndexedPrefixRule`, `MAX_PREFIX_RULES` re-export; tests).
- Test: `zygisk/src/filter.rs` `mod tests`.

- [ ] **Step 1: pure matchers in filter.rs**

Append after the `is_vpn_iface_cstr` block (before `compact_lines`):

```rust
// ============================================================================
//  Global IPv6 prefix rules (design spec §11; wire `prefix` record §4.3)
// ============================================================================

use vpnhide_protocol::PrefixRule;

/// Backend cap, re-exported so the hook layer sizes its per-call resolve
/// array without importing the protocol crate separately. Keep in sync with
/// `MAX_PREFIX_RULES` in kmod/shared/vpnhide_logic.h (protocol §4.3).
pub const MAX_PREFIX_RULES: usize = vpnhide_protocol::MAX_PREFIX_RULES;

/// Bit-exact parity with C `vpnhide_prefix_match` (kmod/shared/vpnhide_logic.h):
/// compare the full bytes, then the top `rem` bits of the boundary byte.
/// `prefix_len` 0 matches every address; > 128 never matches (defensive —
/// the wire parser already caps at 128, like the C).
pub fn prefix_match(addr: &[u8; 16], rule_addr: &[u8; 16], prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    let full = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    if addr[..full] != rule_addr[..full] {
        return false;
    }
    if rem != 0 {
        let mask = 0xffu8 << (8 - rem);
        if (addr[full] ^ rule_addr[full]) & mask != 0 {
            return false;
        }
    }
    true
}

/// True when a rule names `ifname` (byte-exact, NUL-trimmed by the caller)
/// AND its prefix covers `addr`.
pub fn prefix_rule_hit(rules: &[PrefixRule], ifname: &[u8], addr: &[u8; 16]) -> bool {
    rules
        .iter()
        .any(|r| r.ifname.as_bytes() == ifname && prefix_match(addr, &r.addr, r.prefix_len))
}

/// Parse exactly 32 hex chars (any case) into 16 network-order bytes — the
/// address-token shape in `/proc/net/if_inet6` and `/proc/net/ipv6_route`
/// (same 32-hex form as the wire `prefix` record, §4.3).
fn parse_addr32_hex(tok: &[u8]) -> Option<[u8; 16]> {
    if tok.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = parse_hex_u32(&tok[2 * i..2 * i + 1])?;
        let lo = parse_hex_u32(&tok[2 * i + 1..2 * i + 2])?;
        out[i] = ((hi as u8) << 4) | lo as u8;
    }
    Some(out)
}
```

NOTE: `parse_hex_u32` (`filter.rs:209-221`) parses up to 8 chars and shifts — feeding it a 1-char slice returns that nibble. VERIFY this reuse reads correctly; if the implementer finds it unclear, a tiny `hex_nibble(b: u8) -> Option<u8>` helper is acceptable — keep ONE nibble-decoder for the file.

- [ ] **Step 2: config plumbing in lib.rs**

a. `ZygiskConfig` gains (after the `debug` field):

```rust
    /// Global IPv6 prefix rules (§4.3 `prefix` records) from the same
    /// targets.txt snapshot. Applied only inside hooked (target-app)
    /// processes — which IS the kernel's reader-uid gate by construction:
    /// hooked uids are app uids >= 10000, and system_server is never
    /// specialized by this module.
    prefixes: Vec<protocol::PrefixRule>,
```

b. `load_config_from_dir_fd`: the `empty` literal gains `prefixes: Vec::new()`. The `Some(cfg)` arm restructures to MOVE prefixes out (no clone):

```rust
    match protocol::parse_config(&content) {
        Some(cfg) => {
            let protocol::Config {
                debug,
                targets,
                mut prefixes,
            } = cfg;
            // Defensive cap, same as the native parsers (activator already
            // truncates at 8; a hand-written snapshot could carry more).
            prefixes.truncate(protocol::MAX_PREFIX_RULES);
            ZygiskConfig {
                targets: targets
                    .iter()
                    .filter_map(|t| {
                        let hookmask = t.hookmask & ZYGISK_HOOK_MASK;
                        (hookmask != 0).then_some(protocol::Target {
                            uid: t.uid,
                            hookmask,
                        })
                    })
                    .collect(),
                debug: debug.unwrap_or(false),
                prefixes,
            }
        }
        None => { /* unchanged reject arm */ }
    }
```

c. New accessor (near `target_hookmask`):

```rust
/// The cached global prefix rules: empty until `on_load` parses targets.txt,
/// and empty on parse failure (fail closed = no prefix filtering). Read-only
/// after `on_load`, so hook threads race nothing — the `OnceLock` write in
/// `on_load` happens-before `post_app_specialize` installs any hook.
pub(crate) fn prefix_rules() -> &'static [protocol::PrefixRule] {
    CACHED_CONFIG
        .get()
        .map(|cfg| cfg.prefixes.as_slice())
        .unwrap_or(&[])
}
```

d. `debug!` line in `on_load` gains the rule count: `"on_load: {} zygisk targets cached, {} prefix rules, debug={}"`.

- [ ] **Step 3: host tests (filter.rs `mod tests`)**

```rust
    fn rule(ifname: &str, addr: [u8; 16], plen: u8) -> PrefixRule {
        PrefixRule {
            ifname: ifname.to_string(),
            addr,
            prefix_len: plen,
        }
    }

    #[test]
    fn prefix_match_plen_zero_matches_everything() {
        let any = [0xabu8; 16];
        assert!(prefix_match(&any, &[0u8; 16], 0));
        assert!(prefix_match(&[0u8; 16], &[0xffu8; 16], 0));
    }

    #[test]
    fn prefix_match_boundary_byte_and_off_by_one() {
        // 2409:40e3::/32 — the Jio blanket shape.
        let rule_addr: [u8; 16] = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut inside = rule_addr;
        inside[4] = 0xab; // first byte AFTER the /32 — must not matter
        inside[15] = 0xff;
        assert!(prefix_match(&inside, &rule_addr, 32));
        let mut outside = rule_addr;
        outside[3] ^= 0x01; // last bit of the boundary byte
        assert!(!prefix_match(&outside, &rule_addr, 32));
        outside = rule_addr;
        outside[2] ^= 0x80; // first bit of byte 2 (inside /32)
        assert!(!prefix_match(&outside, &rule_addr, 32));
    }

    #[test]
    fn prefix_match_non_byte_aligned_and_edges() {
        let a: [u8; 16] = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // /31: top 7 bits of byte 3 must match (0xe2 vs 0xe3 differ in bit 0).
        let mut b = a;
        b[3] = 0xe2; // 0b1110_0010 — same top 7 bits as 0xe3
        assert!(prefix_match(&b, &a, 31));
        b[3] = 0xe1; // differs in bit 1 (within the /31)
        assert!(!prefix_match(&b, &a, 31));
        // /128 exact, /127 last bit ignored.
        assert!(prefix_match(&a, &a, 128));
        let mut c = a;
        c[15] = 1;
        assert!(!prefix_match(&c, &a, 128));
        assert!(prefix_match(&c, &a, 127));
        // Defensive: > 128 never matches.
        assert!(!prefix_match(&a, &a, 129));
    }

    #[test]
    fn prefix_rule_hit_scopes_by_ifname() {
        let rules = [rule("rmnet_data1", [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32)];
        let addr = [0x24, 0x09, 0x40, 0xe3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert!(prefix_rule_hit(&rules, b"rmnet_data1", &addr));
        assert!(!prefix_rule_hit(&rules, b"rmnet_data3", &addr)); // same addr, other iface
        assert!(!prefix_rule_hit(&rules, b"rmnet_data1", &[0x26u8; 16])); // not covered
        assert!(!prefix_rule_hit(&[], b"rmnet_data1", &addr)); // empty rules
    }

    #[test]
    fn parse_addr32_hex_shape() {
        assert_eq!(
            parse_addr32_hex(b"240940e3000000000000000000000000"),
            Some([0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            parse_addr32_hex(b"240940E3000000000000000000000000"), // case-liberal
            Some([0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(parse_addr32_hex(b"2409"), None); // short
        assert_eq!(parse_addr32_hex(b"zz0940e3000000000000000000000000"), None);
    }
```

- [ ] **Step 4: self-check + commit**

No local cargo (HARD CONTRACT). Self-checks: `grep -n "prefix" zygisk/src/lib.rs zygisk/src/filter.rs`; rustfmt-by-hand discipline (4-space, trailing commas — CI fmt gates). Commit: `zygisk: parse + carry global prefix rules, add C-parity matchers`. NO push (orchestrator batches).

---

### Task 2: `getifaddrs` prefix path

**Files:**
- Modify: `zygisk/src/hooks.rs` (`hooked_getifaddrs` only + its doc comment).

- [ ] **Step 1: hook change**

In `hooked_getifaddrs` (`hooks.rs:324-366`), hoist the rules once and extend the unlink predicate:

```rust
    // Walk the list using a "previous next-pointer slot" cursor …
    // (existing comment stays). Rules hoisted out of the loop: one OnceLock
    // read per getifaddrs call, empty slice = zero-cost fast path.
    let rules = crate::prefix_rules();
    let mut slot: *mut *mut libc::ifaddrs = ifap;
    unsafe {
        while !(*slot).is_null() {
            let entry = *slot;
            let name_ptr = (*entry).ifa_name;
            let is_vpn = if name_ptr.is_null() {
                false
            } else {
                let name = core::ffi::CStr::from_ptr(name_ptr);
                crate::filter::is_vpn_iface_cstr(name)
            };
            // Global prefix rules (kernel inet6_fill_ifaddr parity): drop a
            // v6 entry whose address falls inside a rule prefix on its iface.
            let is_pfx = if rules.is_empty() || name_ptr.is_null() || (*entry).ifa_addr.is_null()
            {
                false
            } else if (*(*entry).ifa_addr).sa_family as c_int != libc::AF_INET6 {
                false // hard constraint: never filter IPv4
            } else {
                let name = core::ffi::CStr::from_ptr(name_ptr);
                let sin6 = &*((*entry).ifa_addr as *const libc::sockaddr_in6);
                crate::filter::prefix_rule_hit(rules, name.to_bytes(), &sin6.sin6_addr.s6_addr)
            };
            if is_vpn || is_pfx {
                *slot = (*entry).ifa_next;
                // `entry` is intentionally leaked; see the doc comment.
            } else {
                slot = &mut (*entry).ifa_next;
            }
        }
    }
```

Extend the doc comment's "unlinks every entry whose `ifa_name` matches a VPN prefix" sentence with: "…or whose v6 address falls inside a global prefix rule on that interface (the kernel `inet6_fill_ifaddr` path's parity; applies only in hooked target processes — the reader-uid gate is structural, see lib.rs)."

- [ ] **Step 2: self-check + commit**

The pure predicate is host-tested in T1; the hook body is thin unsafe glue (pattern-matched against the existing is_vpn arm — no new unsafe beyond the same-pointer `sin6` cast). `grep -n "is_pfx\|prefix_rules" zygisk/src/hooks.rs`. Commit: `zygisk: getifaddrs unlinks v6 addrs covered by global prefix rules`. NO push.

---

### Task 3: `openat` procfs paths — `if_inet6` + `ipv6_route`

**Files:**
- Modify: `zygisk/src/filter.rs` (`filter_by_last_field_ex`, `filter_if_inet6_buf_ex`, `filter_ipv6_route_buf_ex`, `first_field_addr_hit`; old fns become empty-rule wrappers; tests).
- Modify: `zygisk/src/hooks.rs` (`apply_filter` only).

- [ ] **Step 1: filter.rs ex functions**

Replace the `filter_ipv6_route_buf` / `filter_if_inet6_buf` / `filter_by_last_field` block (:89-140) with:

```rust
/// Filter `/proc/net/ipv6_route` in-place. Interface name is the LAST
/// whitespace-delimited field on each line; the route DESTINATION is the
/// FIRST. Kept wrapper for the no-rules shape.
pub fn filter_ipv6_route_buf(data: &mut [u8]) -> usize {
    filter_ipv6_route_buf_ex(data, &[])
}

/// `ipv6_route` with global prefix rules (kernel `ipv6_route_seq_show`
/// parity): a line also drops when its DESTINATION (first field — the
/// route's own plen is never consulted) falls inside a rule prefix on the
/// egress iface (last field).
pub fn filter_ipv6_route_buf_ex(data: &mut [u8], rules: &[PrefixRule]) -> usize {
    filter_by_last_field_ex(data, rules)
}

/// Filter `/proc/net/if_inet6` in-place. Interface name is the LAST
/// whitespace-delimited field on each line. Kept wrapper for the no-rules
/// shape.
pub fn filter_if_inet6_buf(data: &mut [u8]) -> usize {
    filter_if_inet6_buf_ex(data, &[])
}

/// `if_inet6` with global prefix rules (kernel `if6_seq_show` parity): a
/// line also drops when its address (first field, 32 hex) falls inside a
/// rule prefix on the iface (last field).
pub fn filter_if_inet6_buf_ex(data: &mut [u8], rules: &[PrefixRule]) -> usize {
    filter_by_last_field_ex(data, rules)
}

/// Shared logic: filter lines where the LAST whitespace-delimited field
/// is a VPN interface name (used by ipv6_route and if_inet6). Kept wrapper.
fn filter_by_last_field(data: &mut [u8]) -> usize {
    filter_by_last_field_ex(data, &[])
}

/// Shared logic: last-field VPN-name filtering plus the global prefix-rule
/// path (first-field address hit on a rule-named iface).
fn filter_by_last_field_ex(data: &mut [u8], rules: &[PrefixRule]) -> usize {
    compact_lines(data, |line| {
        let ifname = extract_last_field(line);
        if !ifname.is_empty() && is_vpn_iface_bytes(ifname) {
            return true;
        }
        first_field_addr_hit(line, ifname, rules)
    })
}

/// Prefix-rule check for the if_inet6/ipv6_route line shapes: parse the
/// FIRST whitespace-delimited field as a 32-hex v6 address and test it
/// against the rules naming `ifname`. Empty rules / empty ifname / a
/// non-32-hex first field are all a cheap miss.
fn first_field_addr_hit(line: &[u8], ifname: &[u8], rules: &[PrefixRule]) -> bool {
    if rules.is_empty() || ifname.is_empty() {
        return false;
    }
    let field_len = line
        .iter()
        .position(|&b| b == b' ' || b == b'\t' || b == b'\n')
        .unwrap_or(line.len());
    let Some(addr) = parse_addr32_hex(&line[..field_len]) else {
        return false;
    };
    prefix_rule_hit(rules, ifname, &addr)
}
```

- [ ] **Step 2: `apply_filter` wiring (hooks.rs:677-702)**

```rust
fn apply_filter(data: &mut [u8], kind: ProcNetFile) -> usize {
    use crate::filter::*;

    let rules = crate::prefix_rules();
    match kind {
        ProcNetFile::Route => filter_route_buf(data),
        ProcNetFile::Ipv6Route => filter_ipv6_route_buf_ex(data, rules),
        ProcNetFile::IfInet6 => filter_if_inet6_buf_ex(data, rules),
        // … tcp/tcp6/udp/udp6/dev arms unchanged …
    }
}
```

- [ ] **Step 3: host tests**

```rust
    const PFX_RMNET1: [u8; 16] = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn if_inet6_ex_drops_covered_addr_on_rule_iface() {
        let rules = [rule("rmnet_data1", PFX_RMNET1, 32)];
        let input = b"240940e3000000000000000000000001 00000005 40 00 00 rmnet_data1\n\
                      24094123000000000000000000000001 00000007 40 00 00 rmnet_data3\n\
                      fe800000000000000000000000000001 00000005 40 00 00 rmnet_data1\n";
        let mut buf = input.to_vec();
        let n = filter_if_inet6_buf_ex(&mut buf, &rules);
        let out = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(!out.contains("240940e3"), "covered addr on rule iface dropped");
        assert!(out.contains("24094123"), "other iface kept (rules scope by name)");
        assert!(out.contains("fe800000"), "link-local kept (not covered by /32)");
    }

    #[test]
    fn if_inet6_no_rules_is_byte_identical() {
        let input = b"240940e3000000000000000000000001 00000005 40 00 00 rmnet_data1\n";
        let mut buf = input.to_vec();
        let n = filter_if_inet6_buf_ex(&mut buf, &[]);
        assert_eq!(&buf[..n], input);
    }

    #[test]
    fn ipv6_route_ex_drops_covered_destination_keeps_defaults() {
        let rules = [rule("rmnet_data1", PFX_RMNET1, 32)];
        let input = b"240940e3000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 rmnet_data1\n\
                      00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000000 00000000 00000001 rmnet_data1\n\
                      fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 rmnet_data1\n";
        let mut buf = input.to_vec();
        let n = filter_ipv6_route_buf_ex(&mut buf, &rules);
        let out = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(!out.contains("240940e3"), "covered destination dropped");
        assert!(out.contains("00000000000000000000000000000000 00"), "default ::/0 kept — not inside a /32");
        assert!(out.contains("fe800000"), "fe80 kept");
    }

    #[test]
    fn ipv6_route_ex_plen_zero_rule_covers_default() {
        // C parity: plen 0 matches every destination on the rule iface,
        // including ::/0. The route line's own plen field is never consulted.
        let rules = [rule("rmnet_data1", [0u8; 16], 0)];
        let input = b"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000000 00000000 00000001 rmnet_data1\n\
                      00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000000 00000000 00000001 rmnet_data3\n";
        let mut buf = input.to_vec();
        let n = filter_ipv6_route_buf_ex(&mut buf, &rules);
        let out = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(out.contains("rmnet_data3"));
        assert!(!out.contains("rmnet_data1"));
    }
```

- [ ] **Step 4: self-check + commit**

`grep -n "filter_by_last_field\b" zygisk/src/filter.rs` (wrapper + call sites consistent); confirm old wrapper names still resolve (existing tests untouched). Commit: `zygisk: openat filters if_inet6 + ipv6_route lines by global prefix rules`. NO push.

---

### Task 4: netlink dump path — `RTM_NEWADDR` + `RTM_NEWROUTE` prefix filtering (scatter/gather-safe)

**Files:**
- Modify: `zygisk/src/filter.rs` (`IndexedPrefixRule`, `IFA_*`/`RTA_DST`/`AF_INET6` consts, `newaddr_prefix_hit`, `newroute_prefix_hit`, `filter_netlink_dump_ex`, `filter_netlink_dump` becomes wrapper; tests).
- Modify: `zygisk/src/hooks.rs` (`resolve_prefix_rules`, `maybe_filter_netlink_buf`, `hooked_recvmsg` scatter/gather path, iovec test addition).

- [ ] **Step 1: filter.rs — indexed rules + message matchers**

In the netlink section (after the `RTA_OIF` const, :251):

```rust
/// `rtattr` type carrying the route destination (`RTA_DST`).
const RTA_DST: u16 = 1;
/// `rtattr` types carrying the interface address in `RTM_NEWADDR`.
/// Kernel parity: `IFA_LOCAL` is `ifa->addr`; `IFA_ADDRESS` is the peer (or
/// the same value when there is no peer) — match LOCAL first, ADDRESS as
/// fallback.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
/// `rtmsg.rtm_family` / `ifaddrmsg.ifa_family` value for IPv6. The prefix
/// paths gate on this — IPv4 is never filtered (hard constraint).
const AF_INET6: u8 = 10;

/// A prefix rule resolved to an interface index. Wire rules name ifaces;
/// netlink messages carry indices, so the hook layer resolves
/// `ifname → if_nametoindex` once per dump (never cached — bearers renumber
/// on every bring-up, and a stale index would filter the wrong iface).
#[derive(Clone, Copy, Debug)]
pub struct IndexedPrefixRule {
    pub index: u32,
    pub addr: [u8; 16],
    pub prefix_len: u8,
}

/// Prefix-rule check for one `RTM_NEWADDR` message (the whole message,
/// starting at the `nlmsghdr`). True when the message is AF_INET6, its
/// interface index is rule-matched, and its `IFA_LOCAL` (fallback
/// `IFA_ADDRESS`) falls inside that rule's prefix.
fn newaddr_prefix_hit(msg: &[u8], if_index: u32, prules: &[IndexedPrefixRule]) -> bool {
    // ifaddrmsg: family(1) plen(1) flags(1) scope(1) index(4) = 8 bytes.
    if prules.is_empty() || msg.len() < NLMSG_HDRLEN + 8 {
        return false;
    }
    let payload = &msg[NLMSG_HDRLEN..];
    if payload[0] != AF_INET6 {
        return false;
    }
    if !prules.iter().any(|r| r.index == if_index) {
        return false;
    }
    let mut local: Option<[u8; 16]> = None;
    let mut address: Option<[u8; 16]> = None;
    let mut pos = 8usize; // rtattrs follow the 8-byte ifaddrmsg
    while pos + 4 <= payload.len() {
        let Some(rta_len) = read_u16_ne(payload, pos) else {
            break;
        };
        let Some(rta_type) = read_u16_ne(payload, pos + 2) else {
            break;
        };
        let rta_len = rta_len as usize;
        if rta_len < 4 || pos + rta_len > payload.len() {
            break;
        }
        if rta_len >= 4 + 16 {
            let bytes: &[u8; 16] = payload[pos + 4..pos + 4 + 16].try_into().ok().unwrap();
            if rta_type == IFA_LOCAL {
                local = Some(*bytes);
            } else if rta_type == IFA_ADDRESS {
                address = Some(*bytes);
            }
        }
        pos += rta_align(rta_len);
    }
    let Some(addr) = local.or(address) else {
        return false;
    };
    prules
        .iter()
        .any(|r| r.index == if_index && prefix_match(&addr, &r.addr, r.prefix_len))
}

/// Prefix-rule check for one `RTM_NEWROUTE` message. True when the message
/// is AF_INET6, its `RTA_OIF` is rule-matched, and its DESTINATION falls
/// inside that rule's prefix. A missing `RTA_DST` means `::/0` — all-zero
/// address, kernel `rt6key.addr` parity (so a plen-0 rule covers it; the
/// route's own `rtm_dst_len` is never consulted).
fn newroute_prefix_hit(msg: &[u8], oif: Option<u32>, prules: &[IndexedPrefixRule]) -> bool {
    if prules.is_empty() || msg.len() < NLMSG_HDRLEN + RTMSG_HDRLEN {
        return false;
    }
    let payload = &msg[NLMSG_HDRLEN..];
    if payload[0] != AF_INET6 {
        return false;
    }
    let Some(oif) = oif else {
        return false;
    };
    if !prules.iter().any(|r| r.index == oif) {
        return false;
    }
    let mut dst = [0u8; 16];
    let mut pos = RTMSG_HDRLEN;
    while pos + 4 <= payload.len() {
        let Some(rta_len) = read_u16_ne(payload, pos) else {
            break;
        };
        let Some(rta_type) = read_u16_ne(payload, pos + 2) else {
            break;
        };
        let rta_len = rta_len as usize;
        if rta_len < 4 || pos + rta_len > payload.len() {
            break;
        }
        if rta_type == RTA_DST {
            if rta_len >= 4 + 16 {
                dst.copy_from_slice(&payload[pos + 4..pos + 4 + 16]);
            }
            break; // malformed-short RTA_DST keeps dst = :: (no match below /0)
        }
        pos += rta_align(rta_len);
    }
    prules
        .iter()
        .any(|r| r.index == oif && prefix_match(&dst, &r.addr, r.prefix_len))
}
```

- [ ] **Step 2: `filter_netlink_dump_ex` + wrapper**

`filter_netlink_dump` (:313-372) becomes the wrapper; the body moves to `_ex` with the two new hide reasons:

```rust
/// Kept wrapper: VPN-index filtering only (no prefix rules).
pub fn filter_netlink_dump(data: &mut [u8], vpn_indices: &[u32]) -> usize {
    filter_netlink_dump_ex(data, vpn_indices, &[])
}

/// `filter_netlink_dump` with global prefix rules: additionally drops
/// AF_INET6 `RTM_NEWADDR` messages whose `IFA_LOCAL`/`IFA_ADDRESS` falls
/// inside a rule prefix on the message's interface, and AF_INET6
/// `RTM_NEWROUTE` messages whose destination falls inside a rule prefix on
/// the output interface (kernel `inet6_fill_ifaddr` / `rt6_fill_node`
/// parity). IPv4 messages are never prefix-filtered.
pub fn filter_netlink_dump_ex(
    data: &mut [u8],
    vpn_indices: &[u32],
    prules: &[IndexedPrefixRule],
) -> usize {
    if (vpn_indices.is_empty() && prules.is_empty()) || data.len() < NLMSG_HDRLEN {
        return data.len();
    }
    // … identical loop to the old body, with the hide computation:
    //
    //     let hide = if (nlmsg_type == RTM_NEWLINK || nlmsg_type == RTM_NEWADDR)
    //         && nlmsg_len >= NLMSG_HDRLEN + 8
    //     {
    //         let if_index = read_u32_ne(data, read_pos + NLMSG_HDRLEN + 4).unwrap_or(0);
    //         vpn_indices.contains(&if_index)
    //             || (nlmsg_type == RTM_NEWADDR
    //                 && newaddr_prefix_hit(&data[read_pos..read_pos + nlmsg_len], if_index, prules))
    //     } else if nlmsg_type == RTM_NEWROUTE && nlmsg_len >= NLMSG_HDRLEN + RTMSG_HDRLEN {
    //         let oif = route_oif(&data[read_pos..read_pos + nlmsg_len]);
    //         match oif {
    //             Some(o) if vpn_indices.contains(&o) => true,
    //             _ => newroute_prefix_hit(&data[read_pos..read_pos + nlmsg_len], oif, prules),
    //         }
    //     } else {
    //         false
    //     };
    //
    // Everything else (compaction, trailing-tail copy) unchanged.
}
```

(The implementer transcribes the full loop from the existing body with exactly this hide-arm change — no other edits.)

- [ ] **Step 3: hooks.rs — rule resolution + wiring**

a. New resolver (next to `collect_vpn_iface_indices`, :1150):

```rust
/// Resolve the global prefix rules to interface indices for this dump.
/// `if_nametoindex` issues ioctl(SIOCGIFINDEX), which our ioctl hook blocks
/// for VPN names — run under the IN_GETIFADDRS guard like
/// `collect_vpn_iface_indices`. Resolved per call, never cached: bearers
/// renumber (rmnet_dataN churn) and a stale index would filter the wrong
/// iface. Empty rules resolve to an empty array without a single syscall.
fn resolve_prefix_rules() -> (
    [crate::filter::IndexedPrefixRule; crate::filter::MAX_PREFIX_RULES],
    usize,
) {
    use crate::filter::{IndexedPrefixRule, MAX_PREFIX_RULES};

    let mut out = [IndexedPrefixRule {
        index: 0,
        addr: [0u8; 16],
        prefix_len: 0,
    }; MAX_PREFIX_RULES];
    let mut n = 0usize;

    let rules = crate::prefix_rules();
    if rules.is_empty() {
        return (out, 0);
    }
    for rule in rules.iter().take(MAX_PREFIX_RULES) {
        let Ok(cname) = std::ffi::CString::new(rule.ifname.as_str()) else {
            continue;
        };
        let idx = IN_GETIFADDRS.with(|f| {
            let prev = f.get();
            f.set(true);
            let i = unsafe { libc::if_nametoindex(cname.as_ptr()) };
            f.set(prev);
            i
        });
        if idx == 0 {
            continue; // iface down/renumbered right now — rule inert this dump
        }
        out[n] = IndexedPrefixRule {
            index: idx,
            addr: rule.addr,
            prefix_len: rule.prefix_len,
        };
        n += 1;
    }
    (out, n)
}
```

b. `maybe_filter_netlink_buf` (:973-1013): after the existing nlmsg_type gate, replace the `collect_vpn_iface_indices` block:

```rust
    let (indices, n) = collect_vpn_iface_indices();
    // Prefix rules only address v6 address/route messages; RTM_NEWLINK has
    // no address semantics and skips the resolve entirely.
    let (prules, m) = if nlmsg_type == crate::filter::RTM_NEWADDR
        || nlmsg_type == crate::filter::RTM_NEWROUTE
    {
        resolve_prefix_rules()
    } else {
        ([crate::filter::IndexedPrefixRule {
            index: 0,
            addr: [0u8; 16],
            prefix_len: 0,
        }; crate::filter::MAX_PREFIX_RULES], 0)
    };
    if n == 0 && m == 0 {
        return ret;
    }

    crate::filter::filter_netlink_dump_ex(data, &indices[..n], &prules[..m]) as isize
```

c. `hooked_recvmsg` scatter/gather path (:851-854): same pair + closure change:

```rust
    let (indices, n) = collect_vpn_iface_indices();
    let (prules, m) = resolve_prefix_rules();
    if n == 0 && m == 0 {
        return ret;
    }
    // … closure becomes:
    //     |data| crate::filter::filter_netlink_dump_ex(data, &indices[..n], &prules[..m])
```

(The single-iovec fast path already funnels through `maybe_filter_netlink_buf` — no change there beyond (b).)

- [ ] **Step 4: host tests (filter.rs)**

Builders + cases (adapt the existing `make_nlmsg`/`make_route_nlmsg` style):

```rust
    fn make_newaddr6(if_index: u32, ifa_local: Option<[u8; 16]>, ifa_address: Option<[u8; 16]>) -> Vec<u8> {
        // nlmsghdr + ifaddrmsg(8) + rtattrs (16-byte payloads each).
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&[10u8, 64, 0, 0]); // family=AF_INET6, plen, flags, scope
        body.extend_from_slice(&if_index.to_ne_bytes());
        for (ty, val) in [(2u16, ifa_local), (1u16, ifa_address)] {
            if let Some(a) = val {
                body.extend_from_slice(&(4u16 + 16).to_ne_bytes()); // rta_len
                body.extend_from_slice(&ty.to_ne_bytes());
                body.extend_from_slice(&a);
            }
        }
        let total = (NLMSG_HDRLEN + body.len()) as u32;
        let mut msg = Vec::new();
        msg.extend_from_slice(&total.to_ne_bytes());
        msg.extend_from_slice(&RTM_NEWADDR.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    fn make_newroute6(oif: u32, dst: Option<[u8; 16]>) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&[10u8, 0, 0, 0, 254, 3, 0, 1]); // rtmsg, family AF_INET6
        body.extend_from_slice(&0u32.to_ne_bytes());
        body.extend_from_slice(&8u16.to_ne_bytes()); // RTA_OIF
        body.extend_from_slice(&RTA_OIF.to_ne_bytes());
        body.extend_from_slice(&oif.to_ne_bytes());
        if let Some(d) = dst {
            body.extend_from_slice(&(4u16 + 16).to_ne_bytes());
            body.extend_from_slice(&RTA_DST.to_ne_bytes()); // = 1
            body.extend_from_slice(&d);
        }
        let total = (NLMSG_HDRLEN + body.len()) as u32;
        let mut msg = Vec::new();
        msg.extend_from_slice(&total.to_ne_bytes());
        msg.extend_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    const PFX: [u8; 16] = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn prule(index: u32, addr: [u8; 16], plen: u8) -> IndexedPrefixRule {
        IndexedPrefixRule { index, addr, prefix_len: plen }
    }
```

Tests:

```rust
    #[test]
    fn newaddr6_dropped_by_local_prefix() {
        let inside = [0x24, 0x09, 0x40, 0xe3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut buf = Vec::new();
        buf.extend(make_newaddr6(5, Some(inside), None)); // covered — drop
        buf.extend(make_newaddr6(6, Some(inside), None)); // same addr, other index — keep
        let prules = [prule(5, PFX, 32)];
        let n = filter_netlink_dump_ex(&mut buf, &[], &prules);
        assert_eq!(n, buf.len() / 2);
        assert_eq!(read_u32_ne(&buf, NLMSG_HDRLEN + 4), Some(6));
    }

    #[test]
    fn newaddr6_falls_back_to_ifa_address() {
        let inside = [0x24, 0x09, 0x40, 0xe3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut buf = make_newaddr6(5, None, Some(inside));
        let prules = [prule(5, PFX, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut buf, &[], &prules), 0);
    }

    #[test]
    fn newaddr6_ipv4_never_filtered() {
        // Same bytes but family = AF_INET (2): hard-constraint gate.
        let mut msg = make_newaddr6(5, Some([0x24, 0x09, 0x40, 0xe3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]), None);
        msg[NLMSG_HDRLEN] = 2; // ifa_family = AF_INET
        let len = msg.len();
        let prules = [prule(5, PFX, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut msg, &[], &prules), len);
    }

    #[test]
    fn newroute6_dropped_by_dst_prefix() {
        let inside = [0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut buf = Vec::new();
        buf.extend(make_newroute6(5, Some(inside))); // covered — drop
        buf.extend(make_newroute6(5, Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))); // fe80 — keep
        let prules = [prule(5, PFX, 32)];
        let n = filter_netlink_dump_ex(&mut buf, &[], &prules);
        assert_eq!(n, buf.len() / 2);
    }

    #[test]
    fn newroute6_missing_dst_means_default() {
        // No RTA_DST = ::/0 (all-zero). A plen-0 rule covers it; a /32 doesn't.
        let mut buf = make_newroute6(5, None);
        let plen0 = [prule(5, [0u8; 16], 0)];
        assert_eq!(filter_netlink_dump_ex(&mut buf, &[], &plen0), 0);
        let mut buf2 = make_newroute6(5, None);
        let plen32 = [prule(5, PFX, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut buf2, &[], &plen32), buf2.len());
    }

    #[test]
    fn newroute6_short_dst_rta_is_safe_miss() {
        // rta_len < 20 for RTA_DST: treated as absent (:: — no /32 match).
        let mut msg = make_newroute6(5, Some([0x24, 0x09, 0x40, 0xe3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        // Patch the RTA_DST rta_len down to 4+8 (shorter than 16-byte payload).
        let rta_dst_len_off = NLMSG_HDRLEN + RTMSG_HDRLEN + 8; // after OIF rtattr
        msg[rta_dst_len_off..rta_dst_len_off + 2].copy_from_slice(&(12u16).to_ne_bytes());
        let len = msg.len();
        let prules = [prule(5, PFX, 32)];
        assert_eq!(filter_netlink_dump_ex(&mut msg, &[], &prules), len);
    }

    #[test]
    fn wrapper_unchanged_without_rules() {
        let mut buf = Vec::new();
        buf.extend(make_nlmsg(RTM_NEWADDR, 7));
        buf.extend(make_nlmsg(RTM_NEWADDR, 2));
        let n = filter_netlink_dump(&mut buf, &[7]);
        assert_eq!(n, 24);
    }
```

And in `hooks.rs` `mod iovec_tests` add one scatter/gather case that runs `filter_netlink_dump_ex` with prules across an iovec boundary (same shape as the existing test, two iovecs, a covered `RTM_NEWROUTE` split across the boundary — reuse `filter.rs`'s `make_route_nlmsg`-style builder or hand-roll; the point is the closure type change compiles and filters identically when gathered).

- [ ] **Step 5: self-check + commit**

Greps: `grep -n "filter_netlink_dump\b" zygisk/src/` (wrapper + existing tests still resolve); `grep -n "resolve_prefix_rules\|filter_netlink_dump_ex" zygisk/src/hooks.rs`. Confirm the existing 12+ netlink tests are untouched and still pass semantically (wrapper delegates). Commit: `zygisk: netlink dumps drop v6 addrs + route destinations covered by global prefix rules`. NO push.

---

### Task 5: docs sync

**Files:**
- Modify: `docs/detection-vectors.md`
- Modify: `docs/diagnostics.md`
- Modify: `docs/protocol.md`

- [ ] **Step 1: detection-vectors.md**

- §3A `getifaddrs()` row, Zygisk cell: `✅ unlinks VPN nodes` → `✅ unlinks VPN nodes (+ v6 prefix rules)`.
- §3A `RTM_GETADDR dump` row, Zygisk cell: `✅ filter by index` → `✅ filter by index (+ v6 prefix rules)`.
- §3B `/proc/net/ipv6_route` row, Zygisk cell: `✅` → `✅ (+ prefix-rule destinations)`.
- §3B `RTM_GETROUTE dump` row, Zygisk cell: append ` (+ prefix-rule destinations, v6)`.
- §3B paragraph (currently ends "…uid-gated); Zygisk does not implement prefix rules yet."): replace the final clause with — `Zygisk implements the same prefix-rule hiding inside hooked target processes (getifaddrs and RTM_GETADDR v6 addresses, /proc/net/if_inet6 and /proc/net/ipv6_route lines via openat, RTM_GETROUTE v6 dump destinations); the reader-uid gate is structural there — only target apps (uid >= 10000) are ever specialized with hooks.`
- §3C `/proc/net/if_inet6` row, Zygisk cell: `✅ filter_if_inet6_buf` → `✅ filter_if_inet6_buf (+ prefix rules)`.

- [ ] **Step 2: diagnostics.md §7**

READ the real rows first and adapt minimally (same semantic shape as the Phase 5 edits): wherever a v6 address/route row's note says kernel backends hide prefix rules "uid-gated", extend with `; Zygisk: same inside hooked target processes`. Rows to touch (verified at HEAD): `netlink_getroute` (:131), `proc_ipv6_route` (:134), `proc_if_inet6` (:135 — keep its `.ko`-only if6_seq_show carve-out for the KERNEL column; the Zygisk openat coverage note gains prefix rules), plus any `getifaddrs` row if one exists in that table.

- [ ] **Step 3: protocol.md backend table**

Zygisk row (verified :455): config records `` `debug`, `target` (zygisk-owned mask bits) `` → `` `debug`, `target` (zygisk-owned mask bits), `prefix` (global rules, applied inside hooked processes only) ``.

- [ ] **Step 4: commit**

`docs: Zygisk prefix-rule parity on its hooked paths (in target processes)`. NO push. NO changelog fragment (unreleased-feature extension, same as Phases 2-5).

---

### Task 6: push batch + CI gate + artifact

- [ ] Push the T1-T5 commits to `fork feat/ipv6-prefix-filter`. Wait for BOTH workflows green (phase1-check incl. the new zygisk rust checks — first compile of T1-T4 code; kmod-build incl. the new zygisk job). Log-verify in the phase1-check test step output that `vpnhide_zygisk` tests ran (count the new test names).
- [ ] Download the module zip: `gh run download <kmod-build-run> -R awesomeblossom898-spec/vpnhide -n vpnhide-zygisk -d C:/Users/akash/Desktop/PRIVACY/p6-zygisk-artifact` → verify `vpnhide-zygisk.zip` present, unzip -l shows `zygisk/arm64-v8a.so`, `activator`, `module.prop` (record version stamp).
- [ ] Ledger append (`.superpowers/sdd/progress.md`).

---

### Task 7: on-device acceptance (Nord 3, ReZygisk + Termux in-app probes)

Orchestrator-executed (like P4 T7 / P5 T8) — NOT an implementer task. Device: Nord 3, serial may differ per connection (match by model `CPH2487`; `adb reconnect` if empty). Reboot authorized.

**Setup:**

1. Install the module: `adb push` the T6 zip to `/data/local/tmp/` → `su -c 'ksud module install /data/local/tmp/vpnhide-zygisk.zip'` → reboot → verify `/data/adb/modules/vpnhide_zygisk/{zygisk/arm64-v8a.so,activator,service.sh}` exist and `service.sh` ran (logcat `vpnhide` tag: `zygisk: activator finished boot config`).
2. Install Termux (GitHub releases APK, e.g. termux-app_v0.118.x+github-debug_arm64-v8a.apk — download on PC, `adb install`), first launch via `monkey -p com.termux -c android.intent.category.LAUNCHER 1` (bootstrap), wait ~30 s.
3. Build the getifaddrs probe for aarch64 with the local NDK (`kmod/test/gai-probe.c` — the established spec §13 probe): static link, push to `/data/local/tmp/gai-probe`, `chmod 755`. (Termux's `ip` uses netlink, not getifaddrs — the probe covers the T2 acceptance row. If the local NDK lacks a static-capable clang for this, fall back to `termux python3 -c` ctypes `getifaddrs` via `libc.so` — document which was used.)
4. Termux uid: `dumpsys package com.termux | grep -m1 userId=` (expect 10xxx).
5. Canonical JSON: back up `/data/system/vpnhide_config.json` (`cp … /data/local/tmp/vpnhide_config.json.bak`). Write a test JSON = existing content + `com.termux` app entry with native zygisk hook bits (`0x1fc0000` via the schema in `docs/storage.md` / `model.rs`) + the 8-rule blanket as `ipv6PrefixRules` (2 /32s × rmnet_data0-3 — the exact rules already proven on the kernel channel, see P4 T7) + `debug: true`. Run the module activator: `su -c '/data/adb/modules/vpnhide_zygisk/activator'` → verify `targets.txt` now carries `target 0x<termux_uid> 0x1fc0000` + 8 `prefix` lines.

**Probe matrix (each row needs captured evidence in `C:\Users\akash\Desktop\PRIVACY\p6-zygisk-artifact\t7-*.txt`):**

Drive Termux headless: `pm grant com.android.shell com.termux.permission.RUN_COMMAND` (if the intent is denied otherwise), then `am startservice -n com.termux/com.termux.app.RunCommandService -a com.termux.service_execute -e com.termux.extra.command "<cmd> > /sdcard/Android/data/com.termux/files/out.txt 2>&1" -e com.termux.extra.background true` (verify the exact extra keys against the installed Termux version; adapt if renamed). Read output via `adb shell cat /sdcard/Android/data/com.termux/files/out.txt`. Cold-start Termux (force-stop + monkey) AFTER the targets.txt write so hooks install with the new config.

| # | Probe (inside Termux, hooked) | Expect |
|---|---|---|
| 1 | `ip -6 addr show` (netlink RTM_GETADDR → T4) | covered rmnet ifaces show NO global v6 (link-local only) |
| 2 | `gai-probe` (getifaddrs → T2) | no covered-prefix v6 addresses reported |
| 3 | `cat /proc/net/if_inet6` (openat → T3) | covered addr lines ABSENT |
| 4 | `ip -6 route show table all` (netlink RTM_GETROUTE → T4) | covered /64+/128 destinations ABSENT; defaults + fe80 present |
| 5 | `cat /proc/net/ipv6_route` (openat → T3) | covered dst lines ABSENT; fe80/default/lo present |
| 6 | `ip -4 addr show` | v4 untouched (192.0.0.2/27 etc. present) |
| 7 | logcat `-s vpnhide-zygisk` at Termux cold start (debug=1) | `on_load: … 8 prefix rules …` + `pre_app_specialize: targeting uid …` + `selected libc hooks installed` |
| 8 | CONTROL — adb shell (unhooked reader): `cat /proc/net/if_inet6`, `ip -6 route` | truth: covered lines PRESENT |
| 9 | `dumpsys connectivity` | jionet + ims VALIDATED, NOT_VPN (regression gate) |
| 10 | kernel channel untouched: `cat /proc/vpnhide_ctl` | `hooks 0x20003ff error 0x0` (coexistence gate) |

**Cleanup:** restore the backed-up canonical JSON; re-run BOTH activators (module zygisk activator + kmod activator path used in P4 — or re-push `/data/local/tmp/vpnhide_blanket.cfg` to `/proc/vpnhide_ctl` per the existing routine); force-stop Termux. The module stays installed (it's now part of the device stack for Phase 7/8).

- [ ] Ledger append with the verdict per row.

---

### Task 8: phase-final whole-phase review + ledger + handoff

- [ ] Dispatch the whole-phase review (fable-tier) over the full T0-T7 diff + evidence: cross-surface uniformity vs the kernel backends (getifaddrs/inet6_fill, if_inet6/if6_seq, ipv6_route both, rt6/rt6_fill), C-parity of `prefix_match`, v4-untouched gates, scatter/gather safety, fail-closed config, alloc/locking discipline in hooks, docs truthfulness, upstream-PR hygiene (no fork-only files in the eventual PR diff, no `#NN`, no AI mentions).
- [ ] Adjudicate findings (fix Majors+; carry Minors with reasons) → re-gate CI on any fix.
- [ ] Ledger close + rewrite `C:\Users\akash\Desktop\PRIVACY\VPNHIDE_PREFIX_SESSION_HANDOFF.md` for Phase 7 (LSPosed UI).

---

## Self-review notes (orchestrator checklist — do not skip at plan-execute time)

1. **Spec coverage:** design spec §11 asks for getifaddrs + recvmsg prefix filtering, scatter/gather-safe → T2 + T4(c) + the iovec test; "kernel backend remains primary" → no new wire/config surface (T1 reuses targets.txt exactly). §13 test plan → host tests in T1/T3/T4 + on-device probes in T7. §16 conventions → no changelog fragment (unreleased extension), no `#NN`, no AI mentions, docs touched are all upstream-eligible.
2. **Placeholder scan:** every code step carries full code except T4 Step 2's loop body — deliberately a transcription of the existing `filter_netlink_dump` body with the hide-arm diff spelled out inline (the implementer MUST copy the real body; the brief will contain the current body verbatim).
3. **Type consistency:** `IndexedPrefixRule` (filter.rs) = resolver output (hooks.rs) = `_ex` param — same type everywhere; `PrefixRule` (protocol) used by config + procfs filters; wrapper names keep every existing test/caller compiling (`filter_netlink_dump`, `filter_if_inet6_buf`, `filter_ipv6_route_buf`, `filter_by_last_field` unchanged signatures).
4. **Fail-closed posture:** every prefix path no-ops on empty rules; parse failures empty the config (existing behavior); hook failures fall back to original (existing pattern) — no new failure modes.
5. **The one judgment call to double-check at T4:** `IFA_LOCAL`-first with `IFA_ADDRESS` fallback matches kernel `ifa->addr` semantics; matching BOTH would over-hide when a point-to-point peer address sits inside the rule /32 (Jio case: peer is in-block too, so either works on our carrier — LOCAL-first is the precise parity).
