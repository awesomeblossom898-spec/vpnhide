# vpnhide — IPv6 prefix filter design spec

- **Status:** approved design, pre-implementation
- **Date:** 2026-07-18
- **Base:** `okhsunrog/vpnhide` v1.1.1, `main` @ `5cbe367` (PR #243, architecture-boundaries refactor)
- **Target:** additive feature on a fork; upstream PR to `okhsunrog/vpnhide`
- **Devices:** Nord 3 burner (CPH2487, `android12-5.10`, KernelSU) for iteration; OP15 (CPH2745, `android16-6.12`, Jio) for confirmation

---

## 1. Problem & motivation

On rooted Android with a cellular carrier that assigns a global IPv6 via SLAAC, WebRTC (Chrome/browsers) and native code (banking apps enumerating via `getifaddrs()` / `/proc/net/if_inet6` / netlink `RTM_GETADDR`) can read the device's public IPv6 and expose it as a WebRTC ICE host candidate or an identity signal. The internet interface (`rmnet_data1` on the burner) is **dual-stack** — hiding the whole interface is not viable because apps need its IPv4. The goal is to **hide only the global IPv6 addresses matching a prefix on that one interface**, while keeping:

- the IPv4 on that interface visible,
- the IMS interface (`rmnet_data3` on the burner; carries VoLTE/SMS-OTP) fully visible **including its global v6** — critically, the IMS interface has the **same `2401:4900::/32` prefix**, so the rule must be scoped by **interface name**, not prefix alone,
- **no VpnService / no tun** (banking apps refuse to run under a VPN indication).

### Why not the prior RA-drop approach
The earlier ProxyLayer effort removed the address at L3 via RA-drop (`accept_ra=0` + flush). That destabilised IPv6 provisioning on the ROM (constant renumber churn) and is a blunt instrument. vpnhide's technique — leave the address **on** the interface (routing intact) but make it **invisible to enumeration syscalls** — is strictly less disruptive and directly kills the WebRTC/getifaddrs read, which is the actual leak vector.

### Why vpnhide is the right base
It already kretprobe-hooks exactly the kernel surfaces the leak flows through (`inet6_fill_ifaddr` for `RTM_GETADDR`/getifaddrs, `sock_ioctl` for `SIOCGIFCONF`, the route dumps) and uses a clean **skb-rollback** technique (`skb_trim(skb, saved_len)` on kretprobe return) to remove already-written entries from netlink dumps. It supports the exact GKI generations in play (`android12-5.10`, `android16-6.12`) and keeps `NOT_VPN` (no tun).

---

## 2. Goals / non-goals

**Goals**
- New **global** IPv6 prefix rule: hide any v6 matching `{iface_name, prefix, prefix_len}` from **all** callers (apps + shell/root).
- Kill the leak on the address-enumeration surfaces: `inet6_fill_ifaddr` (netlink/getifaddrs) and a **new** `if6_seq_show` hook (`/proc/net/if_inet6`, currently unhooked).
- Leave IPv4 (`inet_fill_ifaddr`) and non-matching interfaces completely untouched.
- Full cross-backend + cross-language parity (`.ko`, KPM, Zygisk; C/Rust/Kotlin) with tests, and an LSPosed UI to author the rules.
- Fresh per-KMI `.ko` zips built via **fork CI**, verified on-device, then an upstream PR.

**Non-goals**
- No VpnService/tun; `TRANSPORT_VPN` must stay false on all networks.
- No IPv4 filtering.
- No server-side leak defence (out of vpnhide's threat model).
- Not hiding root/custom ROM.

---

## 3. How vpnhide filters today (verified against source)

- **Config apply:** `ctl_write()` (`kmod/vpnhide_kmod.c`) reads the text snapshot from `/proc/vpnhide_ctl`, calls `vpnhide_parse_config()` (shared, `kmod/shared/vpnhide_logic.h`) into a temp `struct vpnhide_target newt[MAX_TARGET_UIDS]`, then swaps it under `targets_lock` into `targets[]`/`nr_targets` and recomputes `active_hook_mask` (OR of all hookmasks — a lock-free hot-path gate).
- **Per-UID gate:** every hook entry handler early-returns unless `hook_active(hook_id)` — which checks `active_hook_mask & (1<<id)` then scans `targets[]` for `current_uid()`. So today **everything is per-UID**.
- **The address hook:** `inet6_fill_ifaddr` entry handler reads `ifa = regs->regs[1]` (a `struct inet6_ifaddr *`), which exposes **both** `ifa->addr` (the `struct in6_addr`) and `ifa->idev->dev->name`. If `is_vpn_ifname(dev->name)`, it saves `skb->len`; the return handler does `skb_trim(skb, saved_len)` + `regs_set_return_value(0)`.
- **Seq-file surfaces:** `fib_route_seq_show` (`/proc/net/route`) and `ipv6_route_seq_show` (`/proc/net/ipv6_route`) use `vpnhide_compact_seq_lines()` (shared) to drop VPN-iface lines in place. **`if6_seq_show` (`/proc/net/if_inet6`) is NOT hooked today.**
- **Wire format** (`docs/protocol.md`, frozen v1): header `vpnhide 1 config`; records `debug <0|1>` and `target <uid> <hookmask>`; data fields are `0x`-hex u32/u64; unknown keyword → skip line (forward-compat); a version greater than the reader's is rejected whole.
- **Parity & codegen:** the C parser (`vpnhide_logic.h`) and the Rust parser (`crates/protocol/src/lib.rs`) are independent mirrors kept in sync by golden vectors (`kmod/shared/protocol_vectors.tsv`) + a Rust↔C proptest (`crates/protocol-diff`). The hook-id registry is codegen'd from `data/hooks.toml` via `scripts/codegen-hooks.py` into C/Rust/Kotlin generated headers, with a CI drift check.
- **Activator:** `crates/activator/src/model.rs` parses a JSON canonical (`apps{pkg -> {native, java, ...}}`, `settings{}`) and `project_native_*` resolves packages→UIDs (via PackageManager) into `target` wire lines.

---

## 4. Design overview

Add a **new, orthogonal, global config dimension — "prefix rules" — parallel to the per-UID `target` model.** Rejected alternative: overloading `is_vpn_ifname()`/`data/interfaces.toml` (compile-time VPN-name list) or the per-UID target model — both are the wrong shape for a runtime, global, address-scoped concern. A first-class `prefix` record keeps v4 and other interfaces untouched and rides the format's forward-compat rule so the wire stays **version 1**.

---

## 5. Wire format extension (`docs/protocol.md` §4.3)

New config record (global; no UID field):

```
prefix <ifname> <addr32hex> <plen_hex>
```

- `ifname` — ASCII token, ≤ `IFNAMSIZ-1` (15) chars, e.g. `rmnet_data1`.
- `addr32hex` — **exactly 32 hex chars**, network byte order (e.g. `24014900000000000000000000000000` = `2401:4900::`). Read is liberal on case (accepts `A-F`/`a-f`); write always emits lowercase — same liberal-in/strict-out contract as §4.4. Not 32 chars, or a non-hex char → reject that line. This matches the kernel's own `/proc/net/if_inet6` spelling. **Documented deviation** from §4.4's mandatory-`0x` primitive: an IPv6 address is 128-bit and does not fit the u32/u64 primitive; the fixed-width bare-hex form is unambiguous and shell-safe. Pinned in `protocol.md` + golden vectors.
- `plen_hex` — `0x`-prefixed prefix length, `0x0`..`0x80` (0..128), e.g. `0x20` for /32.
- **Semantics:** global — matches regardless of `current_uid()`. A v6 address on interface `ifname` whose first `plen` bits equal the rule's prefix is hidden.
- **Forward-compat:** unknown-keyword-skip means a stock v1 backend ignores `prefix` lines; we keep `version 1`. Snapshot semantics unchanged (one write = whole desired state).

**Example (burner):**
```
vpnhide 1 config
debug 1
prefix rmnet_data1 24014900000000000000000000000000 0x20
```
Hides any global v6 in `2401:4900::/32` **on `rmnet_data1` only**; `rmnet_data3` (same prefix, different iface) is untouched. On OP15/Jio the iface names differ (IMS may be `rmnet_data1`), so the `ifname` is re-derived per device.

---

## 6. Shared freestanding logic (`kmod/shared/vpnhide_logic.h`)

New data + pure helpers (no libc / no kernel headers — the freestanding contract shared by `.ko` and KPM):

```c
#ifndef MAX_PREFIX_RULES
#define MAX_PREFIX_RULES 8
#endif

struct vpnhide_prefix_rule {
    char          ifname[VPNHIDE_IFNAMSIZ]; /* NUL-terminated */
    unsigned char addr[16];                 /* network order  */
    unsigned char prefix_len;               /* 0..128         */
};

/* parse exactly 32 hex chars -> 16 bytes; 1 on success */
static inline int vpnhide_tok_addr32(const char *b, unsigned long ts,
                                     unsigned long te, unsigned char out[16]);

/* copy an ifname token into dst[VPNHIDE_IFNAMSIZ]; 1 on success (fits) */
static inline int vpnhide_tok_ifname(const char *b, unsigned long ts,
                                     unsigned long te, char *dst);

/* first prefix_len bits of addr == rule->addr ? (boundary-byte masked) */
static inline int vpnhide_prefix_match(const unsigned char addr[16],
                                       const struct vpnhide_prefix_rule *r);
```

- Extend `vpnhide_parse_config()` with prefix out-params `(struct vpnhide_prefix_rule *prules, int max_prules, int *nr_prules)` — the single-source-of-truth parse. Add an `else if (tok == "prefix")` arm using the new helpers. Callers to update: `ctl_write` (`.ko`), the KPM apply path, and `test_protocol.c`. (Alternative considered: a second `vpnhide_parse_prefix_rules()` pass — rejected to keep one coherent snapshot parse.)
- Add `vpnhide_compact_if_inet6_lines()` for the new `/proc/net/if_inet6` hook: parse the **first** field (32-hex addr) + **last** field (ifname) per line, drop lines matching a prefix rule (global) or `is_vpn_ifname` (per-UID) — same in-place down-copy compaction pattern as `vpnhide_compact_seq_lines()`.

---

## 7. Kernel `.ko` changes (`kmod/vpnhide_kmod.c`)

- **State:** `static struct vpnhide_prefix_rule prefix_rules[MAX_PREFIX_RULES]; static int nr_prefix_rules;` under `targets_lock`, plus a lock-free `static bool prefix_rules_present;` (`WRITE_ONCE` on apply) hot-path gate. `ctl_write` parses + swaps them alongside targets.
- **`inet6_fill_ifaddr` (core leak fix):** in the entry handler, after the existing per-UID VPN check, add an **independent** path:
  ```c
  if (!data->should_filter && READ_ONCE(prefix_rules_present) &&
      ifa && ifa->idev && ifa->idev->dev &&
      prefix_rule_hits(ifa->idev->dev->name, &ifa->addr)) {
      data->skb = (struct sk_buff *)regs->regs[0];
      data->saved_len = data->skb ? data->skb->len : 0;
      data->should_filter = true;
  }
  ```
  `prefix_rule_hits()` snapshots/scans `prefix_rules[]` (concurrency: reuse `targets_lock`, consistent with the existing `hook_active` per-syscall scan; or an RCU-published copy). Return handler unchanged (`skb_trim`). Note: this fires even when no `target` uses `inet6_fill_ifaddr`, because the kretprobe is always registered and the gate is `prefix_rules_present`, not `hook_active`.
- **New hook `if6_seq_show`** (`/proc/net/if_inet6`): register a kretprobe in the `hooks[]` table; add a new kernel hook id in `data/hooks.toml` + regen. Its return handler runs `vpnhide_compact_if_inet6_lines()` over the seq buffer, hiding VPN ifaces (per-UID via `hook_active`) **and** prefix matches (global). This also closes a real detection-vector gap for the VPN-hiding feature.
- **v4 untouched:** `inet_fill_ifaddr` gets **no** prefix logic.
- **Secondary (Phase 4):** extend `rt6_fill_node` (`RTM_GETROUTE` v6) and `ipv6_route_seq_show` (`/proc/net/ipv6_route`) to also drop v6 routes whose dst/nexthop falls in a configured prefix on the configured iface. Not needed for the WebRTC/getifaddrs leak (which reads addresses) — phased after the core is proven.

---

## 8. Cross-language parity (protocol §8)

- **Rust** (`crates/protocol/src/lib.rs`): add `PrefixRule { ifname: String, addr: [u8;16], prefix_len: u8 }`, parse the `prefix` record, and format it; add to `Config`.
- **Kotlin** app parser: mirror the same (path located in Phase 3/7).
- **Golden vectors** (`kmod/shared/protocol_vectors.tsv`): extend the `cfg` expected string to also serialise parsed prefix rules (e.g. append `;pfx:<iface>:<addr32hex>:<plen>`), plus dedicated rows for the address-token edge cases (short/long/odd hex → reject line; boundary `plen` 0 and 0x80). Consumed by the C (`test_protocol.c`), Rust (`golden_vectors`), and Kotlin tests.
- **Diff oracle** (`crates/protocol-diff`): extend the proptest generator to emit `prefix` lines so C↔Rust divergence is caught.
- **Registry:** add `if6_seq_show` to `data/hooks.toml`, run `python3 scripts/codegen-hooks.py`, commit the regenerated C/Rust/Kotlin hook-id files (CI drift check).

---

## 9. Activator + JSON schema (`crates/activator`)

- Add a top-level (global, not per-app) field to the canonical JSON:
  ```json
  "ipv6PrefixRules": [
    { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 32 }
  ]
  ```
  (`model.rs`: new struct + `serde`; accept `prefix` as colon-notation IPv6 in JSON and normalise to 32-hex when projecting to the wire.)
- `project_native_*` appends a `prefix <iface> <addr32hex> <plen>` line per rule (kmod + KPM projections). Bounded by `MAX_PREFIX_RULES` with an over-cap warning, mirroring the target-cap behaviour.

---

## 10. KPM parity (`kmod/kpm/vpnhide_kpm.c`)

Reuses the shared `vpnhide_parse_config` (prefix parsing free). Add the same match calls in its KernelPatch inline hook bodies for `inet6_fill_ifaddr` and `if6_seq_show` (and, Phase 4, the v6 route hooks), using the shared `vpnhide_prefix_match` / `vpnhide_compact_if_inet6_lines`. Must remain single-active vs the `.ko` (existing kernel guard).

---

## 11. Zygisk (Rust libc hooks) — lower priority

Add prefix filtering to `getifaddrs`/`recvmsg` hooks, scatter/gather-safe per commit `04f772e`. Userspace and raw-syscall-bypassable, so the kernel backend remains primary; included for completeness of "everything".

---

## 12. LSPosed UI (Kotlin Compose) — last phase

A small "IPv6 prefix rules" editor (iface, prefix, length) that writes into the canonical JSON consumed by the activator. Largest/most-uncertain surface (Compose + storage + ktlint/detekt gates); phased last. Non-UI proof (JSON edit + activator, or manual `echo` to `/proc/vpnhide_ctl`) is sufficient for the core acceptance criteria.

---

## 13. Test plan

- **Host protocol** (`kmod/shared/test_protocol.c` + vectors): prefix parse/format, address-token edges, `plen` boundaries. Runs under gcc; also in CI.
- **Shared logic** (`kmod/test_vpnhide_logic.c`, `kmod/test_iface_lists.c`): unit-test `vpnhide_prefix_match` (boundary byte, /0, /128, off-by-one) and `vpnhide_compact_if_inet6_lines`.
- **Rust:** `cargo test` (golden vectors + proptest diff oracle).
- **QEMU** (`kmod/test/`): boot the `.ko`, apply a prefix config, assert `if_inet6`/netlink behaviour without a device.
- **On-device native probes:** `kmod/test/gai-probe.c` (getifaddrs) and `ifconf-probe.c` (SIOCGIFCONF) — the exact "native leak test" the acceptance criteria call for.

---

## 14. Build & on-device verification

**Build (fork CI):** fork → branch → GitHub Actions builds `vpnhide-kmod-android12-5.10.zip` + `vpnhide-kmod-android16-6.12.zip` (DDK matrix must include both KMIs) → download artifacts. No local Docker/Rust needed. Host + Rust tests run in the same CI.

**Install (Nord 3):** `adb push` the zip → KernelSU manager → Install from storage → reboot → confirm `lsmod | grep vpnhide`, `dmesg | grep vpnhide`, `cat /proc/vpnhide_ctl`. Apply:
```
echo 'vpnhide 1 config
debug 1
prefix rmnet_data1 24014900000000000000000000000000 0x20' > /proc/vpnhide_ctl
```

**Acceptance matrix (Nord 3, then repeat on OP15/Jio with device-correct ifnames):**
- `ip -6 addr show dev rmnet_data1` → global v6 gone; `dev rmnet_data3` → IMS v6 present.
- `cat /proc/net/if_inet6` → rmnet_data1 v6 entry absent; rmnet_data3 present.
- `ip -4 addr show dev rmnet_data1` → v4 present.
- `dumpsys connectivity` → internet + IMS both `VALIDATED`; all networks `NOT_VPN` (no `TRANSPORT_VPN`).
- pixelscan.net / browserleaks.com → no global v6 in WebRTC ICE candidates.
- `gai-probe` → v6 on rmnet_data1 absent.
- VoLTE call connects; SMS-OTP arrives.
- ProxyLayer (`/data/adb/modules/proxylayer/`) coexists: vpnhide (netlink/getifaddrs) vs ProxyLayer (iptables/mangle) are orthogonal; sanity-check no interaction.

---

## 15. Risks & mitigations

- **rmnet renumbering** — exact-name scoping breaks if the internet iface renumbers (documented constant Jio renumber churn). *Mitigation:* re-apply config on renumber (boot/heartbeat re-push of the snapshot); inherent to name-scoping, which is required to protect the same-prefix IMS iface.
- **Global hide vs `system_server`** — `inet6_fill_ifaddr` also serves the `RTM_NEWADDR` notify path, so a global rule can make system_server see the iface as v6-less. The address stays functional (routing intact) and prior RA-drop *removed* it with connectivity still `VALIDATED`, so this should be no worse; the `dumpsys ... VALIDATED` check is the gate. If it regresses, fall back to scoping the prefix path by target UID.
- **Concurrency** — prefix scan in the netlink dump path must be safe under the existing rcu/lock model; snapshot under `targets_lock` or publish via RCU.
- **Upstream taste** — the `addr32hex` deviation from the `0x` primitive and the "global (UID-less)" record are new shapes; `protocol.md` is updated as the arbiter with vectors, and the PR frames them explicitly for the maintainer.

---

## 16. PR plan & repo conventions (from `CLAUDE.md`)

- Regular PR (not draft) to `okhsunrog/vpnhide`.
- Changelog fragment via `./scripts/changelog.py added "<EN>" "<RU>"` before committing user-visible changes; do **not** bump `VERSION` / run `release.py`.
- No `#NN` local-note refs; no AI-tool mentions in commits/PR/changelog.
- Update `docs/protocol.md` (arbiter), `docs/state.md`, `docs/storage.md`.
- Keep this `docs/superpowers/` spec **out** of the upstream PR diff.

---

## 17. Phasing / milestones

1. **Wire + parser + shared match + host tests** (fully local-testable).
2. **`.ko`: `inet6_fill_ifaddr` prefix path + new `if6_seq_show` hook + codegen** → build via CI → **on-device proof of the core leak fix** (the acceptance matrix minus routes).
3. **Rust + Kotlin parity + activator JSON schema** (diff oracle green).
4. **v6 route hooks** (`rt6_fill_node`, `ipv6_route_seq_show`).
5. **KPM parity.**
6. **Zygisk parity.**
7. **LSPosed UI.**
8. **Upstream PR** (design note + tests + `protocol.md` extension), then confirm on OP15/Jio.

---

## Appendix A — touch-point files (verified)

- `kmod/shared/vpnhide_logic.h` — structs, helpers, `vpnhide_parse_config` extension, if_inet6 compaction.
- `kmod/vpnhide_kmod.c` — prefix state, `inet6_fill` path, `if6_seq_show` hook + `hooks[]` table, `ctl_write` apply.
- `kmod/kpm/vpnhide_kpm.c` — KPM inline-hook parity.
- `kmod/shared/test_protocol.c`, `kmod/shared/protocol_vectors.tsv`, `kmod/test_vpnhide_logic.c`, `kmod/test_iface_lists.c` — tests.
- `kmod/generated/hook_ids.h`, `crates/protocol/src/generated/hook_ids.rs` — regenerated.
- `data/hooks.toml`, `scripts/codegen-hooks.py` — new hook id.
- `crates/protocol/src/lib.rs`, `crates/protocol-diff/src/lib.rs` — Rust parse/format + diff oracle.
- `crates/activator/src/model.rs`, `crates/activator/src/lib.rs` — JSON schema + projection.
- `lsposed/**` — Kotlin parser + UI (paths located in Phase 3/7).
- `docs/protocol.md`, `docs/state.md`, `docs/storage.md`, `changelog.d/` — docs + changelog.
- `.github/workflows/ci.yml` — confirm KMI matrix includes `android12-5.10` + `android16-6.12`.

## Appendix B — canonical JSON ⇄ wire example

JSON (`/data/system/vpnhide_config.json`):
```json
{ "version": 1, "debug": true,
  "ipv6PrefixRules": [ { "iface": "rmnet_data1", "prefix": "2401:4900::", "prefixLen": 32 } ] }
```
Projected wire (`/proc/vpnhide_ctl`):
```
vpnhide 1 config
debug 1
prefix rmnet_data1 24014900000000000000000000000000 0x20
```
