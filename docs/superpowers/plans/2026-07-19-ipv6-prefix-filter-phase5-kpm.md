# IPv6 Prefix Filter — Phase 5 (KPM parity) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the KPM backend (`kmod/kpm/vpnhide_kpm.c`) full global IPv6 prefix-rule parity with the `.ko`: prefix state via the shared parser, uid-gated filtering on its three relevant hook paths (inet6_fill_ifaddr, ipv6_route_seq_show, rt6_fill_node), and sentinel-uid global stats — with a first-ever fork CI compile gate.

**Architecture:** KPM already includes the freestanding `kmod/shared/vpnhide_logic.h` (parser, `vpnhide_prefix_match`, `vpnhide_uid_prefix_filtered`, `vpnhide_compact_if_inet6_lines`, `vpnhide_streq`) — this phase wires it in. No new hook ids, no mask changes (`KPM_HOOK_MASK = 0x3ff` stays; KPM owns no `if6_seq_show` — `/proc/net/if_inet6` remains uncovered on KPM by design). Locking follows the KPM's existing seqlock (`cfg_seq`) discipline, NOT the `.ko`'s spinlock (KP has no kernel spinlock API). Stats attribution mirrors the merged `.ko` "enabled" semantics (`uid_target = active`).

**Tech Stack:** freestanding C (KernelPatch environment — clang, no libc beyond what KP provides, no spinlock/RCU/memcpy guarantees), GitHub Actions (fork CI), ksud on-device probe.

---

## Verified facts (do not re-derive)

1. **KPM today** (`kmod/kpm/vpnhide_kpm.c`, 1299 lines, ZERO `prefix` references): ctl0 CONFIG arm calls `vpnhide_parse_config(args, n_args, new_targets, MAX_TARGET_UIDS, &dbg)` — the wrapper at `kmod/shared/vpnhide_logic.h:866` that DISCARDS prefix rules (`return vpnhide_parse_config_ex(b, len, out, max, debug, 0, 0, 0);`). So a `prefix` line sent to the KPM today parses fine and is silently dropped.
2. **Shared `_ex` signature** (`vpnhide_logic.h:799`): `vpnhide_parse_config_ex(const char *b, unsigned long len, struct vpnhide_target *out, int max, int *debug, struct vpnhide_prefix_rule *pout, int pmax, int *pnr)` — param order proven by the wrapper call above.
3. **`struct vpnhide_prefix_rule`** (`vpnhide_logic.h:327`): `{ char ifname[16]; unsigned char addr[16]; unsigned char prefix_len; }` — 33 bytes, alignment 1. `MAX_PREFIX_RULES` = 8 (`:321`, `#ifndef`-guarded).
4. **Sentinel `VPNHIDE_GLOBAL_STATS_UID`** is `#define`d ONLY in `kmod/vpnhide_kmod.c:205` as `((uid_t) - 1)` (comment :203-204). `struct vpnhide_stat_entry.uid` is `unsigned int` (`vpnhide_logic.h:336-340`), so a shared `((unsigned int) - 1)` define is value-identical (0xFFFFFFFF on the wire; Rust/Kotlin sides are wire-level, no constant to sync — VERIFY by grep in T1).
5. **KPM locking idiom**: `cfg_seq` seqlock (odd = writer mid-update) + `cfg_writer` CAS gate (`cfg_try_write_begin`/`cfg_write_end`, `vpnhide_kpm.c:142-157`). Readers retry on odd/changed seq — see `hook_active` (`:164-189`) for the exact read-side pattern to mirror. No spinlocks in KP.
6. **KPM stats idiom**: lock-free slot table `stats_used/stats_uids/stats_counts` (`:98-102`), `record_hook_hit` (:237) uses `current_uid()`; `snapshot_stats` (:248) fills `vpnhide_stat_entry[]`. The `.ko`'s Fix-A sentinel row lives in a SEPARATE fixed array `global_hook_counts[VPNHIDE_HOOK_COUNT]` appended AFTER per-uid rows at snapshot time (`vpnhide_kmod.c:209-271`) — mirror that shape, atomics only (`__sync_fetch_and_add`), no slot table.
7. **`stats_snapshot` sizing** (`vpnhide_kpm.c:101-102`): `[MAX_TARGET_UIDS * VPNHIDE_HOOK_COUNT]` — must grow by `VPNHIDE_HOOK_COUNT` for the sentinel row's worst case (`.ko` comment "…+1 hook-row of headroom", `vpnhide_kmod.c:73`), and the ctl0 caller's `max` arg (`:1211-1213`) must pass the new bound.
8. **rt6key offset already in the table**: `off->fib6_info_fib6_dst` (rt6key `{ in6_addr addr@0; int plen@16; }`) = 64 on 5.10/6.1, 80 on 6.12, `off->rt6_dst` on the 4.14 rt6_via_dst path; 0 disables (`kver_offsets.h:79-94,140,177,217`). `kpm_is_public_host_route6` (`vpnhide_kpm.c:342-360`) already selects `off->rt6_via_dst ? off->rt6_dst : off->fib6_info_fib6_dst` — the prefix check reuses that select but reads ONLY the 16 addr bytes at `rt + dst_off` (the route's own plen is NEVER consulted — Phase 4 semantics).
9. **inet6_ifaddr addr @ +0**: `struct inet6_ifaddr` begins with `struct in6_addr addr` on every supported kver (the layout the `.ko` compiles against; the KPM file already relies on the struct's stable prefix for `idev@168`, `kver_offsets.h:113`). Read 16 bytes at `fargs->arg1 + 0`.
10. **No memcpy guarantee**: the KernelPatch submodule is NOT vendored locally and the existing KPM file never calls `memcpy` (it byte-copies in `iface_is_vpn`, `:273-281`). All rule-array copies in this plan are BYTE LOOPS in that idiom — do not introduce `memcpy`/`__builtin_memcpy`.
11. **Device reality (Nord 3, verified 2026-07-19)**: `ksud kpm` CLI exists but `ksud kpm num`/`version` → `ENOSYS/ENOTTY` ("Inappropriate ioctl for device"); kernel `5.10.236-android12-OP-RESUKISU-huangdihd` has NO KernelPatch runtime in kallsyms (only `clkpm_*` clock-PM symbols). **On-device KPM load is platform-blocked**; T8 is a probe-and-document task, NOT a full matrix. `ksud module disable/enable vpnhide_kmod` exists (would be the `.ko` stand-down if a future kernel gains KPM).
12. **KPM build** (`kmod/kpm/build.py`): needs host `clang`+`lld`+`make`, the public `kmod/third_party/KernelPatch` submodule (bmax121/KernelPatch), Rust+cargo-ndk for the bundled `kpm` activator bin (`build_activator_bin(repo_root, "kpm")`), `fetch-depth: 0` for `git describe`. Output `vpnhide-kpm.zip` at repo root; leave `UPDATE_JSON_URL` UNSET on the fork (no updateJson → no bad update prompt).
13. **Stock CI kpm job** (`.github/workflows/ci.yml:408-438`) runs in the fork-inaccessible private image but the actual steps are image-independent: checkout (submodules recursive, fetch-depth 0) → apt clang/lld → `python3 kmod/kpm/build.py` → upload artifact. The fork's `prefix-kmod-build.yml` activator job already shows the Rust/cargo-ndk/NDK setup to mirror (`ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_NDK_LATEST_HOME}"`).
14. **Attribution semantics (merged, load-bearing)**: "enabled", NOT "fired": `.ko` rt6 uses `data->uid_target = active;` (commit 2eddc81) — per-uid stats row iff the reader is a target with the hook enabled; sentinel row otherwise. Phase 4 plan amendment d322909 says Phase 5 must mirror this. The `.ko` inet6 uses `uid_target = vpn_active` (`vpnhide_kmod.c:856`); both seq rets use `vpn_match != NULL` → per-uid else global.
15. **Docs that currently say "KPM … do not implement prefix rules yet"**: `docs/detection-vectors.md` §3B paragraph ("The `.ko` additionally hides v6 route **destinations** …; KPM and Zygisk do not implement prefix rules yet.") and its §3C `if_inet6` note is ALREADY correct (KPM doesn't hook it — stays true). `docs/diagnostics.md` §7 `netlink_getroute` note "(KPM: VPN routes only)" and `proc_ipv6_route` note "(KPM: VPN-iface lines only)". `docs/protocol.md` §4.3 is wire-level/backend-agnostic — verify, likely untouched.
16. **Changelog**: pending fragments `changelog.d/added-hide-user-configured-ipv6-prefixes-*.md` + `changed-ipv6-prefix-hiding-now-filters-app-*.md` are path-generic — T6 verifies they stay truthful with KPM parity added (expected: untouched, no new fragment — unreleased-feature extension).

## Scope boundary (unchanged from Phases 1-4)

- IPv4 paths untouched (`inet_fill_ifaddr`, `fib_dump_info`, `fib_route_seq_show`, `fib_nl_fill_rule` keep EXACT current behavior; v4 attribution stays per-uid via the `data3 = 1` default).
- No new hook ids; `KPM_HOOK_MASK`/`KERNEL_HOOK_MASK` unchanged; no codegen changes; no `data/hooks.toml` change.
- `.ko` behavior unchanged (T1 moves a #define the `.ko` already uses — value identical; no logic change).
- Zygisk untouched (Phase 6). LSPosed untouched (Phase 7).
- The reader-uid gate is LOAD-BEARING: prefix filtering ONLY for uid >= 10000 or == 2000; system readers always see truth. Applies identically on KPM.

---

### Task 0: fork CI KPM build gate

**Files:**
- Modify: `.github/workflows/prefix-kmod-build.yml` (append one job)

This job is the FIRST compile of every KPM change in this phase — it must exist and be green before T1-T6 land. One cross-version binary (no matrix).

- [ ] **Step 1: append the job**

Add after the existing `kmod:` job (top-level `jobs:` sibling, same indentation as `activator:`/`kmod:`):

```yaml
  kpm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          submodules: recursive # public KernelPatch headers for `make kpm`
          fetch-depth: 0 # get_build_version's `git describe`

      - name: Mark workspace safe
        run: git config --global --add safe.directory "$GITHUB_WORKSPACE"

      - name: Rust target + cargo-ndk + clang/lld
        run: |
          set -euxo pipefail
          rustup target add aarch64-linux-android
          cargo install cargo-ndk --locked
          sudo apt-get update -qq
          sudo apt-get install -y --no-install-recommends clang lld make

      - name: Build KPM module zip
        run: |
          set -euxo pipefail
          export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_NDK_LATEST_HOME}"
          python3 kmod/kpm/build.py

      - uses: actions/upload-artifact@v7
        with:
          name: vpnhide-kpm
          path: vpnhide-kpm.zip
          if-no-files-found: error
```

Also update the workflow's header comment: after the line ending `NOT for upstream.` add ` The kpm job builds the cross-version KPM zip with the public KernelPatch submodule (stock ci.yml's kpm job needs the private ci image).`

- [ ] **Step 2: commit + push alone, watch the new job**

```bash
git add .github/workflows/prefix-kmod-build.yml
git commit -m "ci: fork KPM build gate on public runner + KernelPatch submodule"
git push fork feat/ipv6-prefix-filter
gh run list -R awesomeblossom898-spec/vpnhide --workflow prefix-kmod-build.yml --limit 1
# watch; then:
gh run view <run> -R awesomeblossom898-spec/vpnhide --log-failed  # only if red
```

Expected: `kpm` job green (produces `vpnhide-kpm.zip` artifact). If red, fix before proceeding — every later task depends on this gate.

---

### Task 1: hoist `VPNHIDE_GLOBAL_STATS_UID` into the shared header

**Files:**
- Modify: `kmod/shared/vpnhide_logic.h` (add the define)
- Modify: `kmod/vpnhide_kmod.c` (remove the local define; keep its comment context accurate)
- Test: existing host suites cover the header (`kmod/shared/test_vpnhide_logic.c`, `kmod/shared/test_protocol.c` — compile is the gate)

Both backends need the sentinel (KPM gains global stats in T2). One definition, freestanding-safe (`uid_t` does NOT exist in the shared header — use `unsigned int`, value-identical: `struct vpnhide_stat_entry.uid` is `unsigned int`).

- [ ] **Step 1: add to the shared header**

In `kmod/shared/vpnhide_logic.h`, immediately ABOVE the `/* one sparse `<hook_id>:<count>` stats cell for a given uid (§4.3). …` comment block that precedes `struct vpnhide_stat_entry`, insert:

```c
/* Sentinel UID for the uid-independent global prefix-hit stats row: prefix-rule
 * matches fired by non-target UIDs are reported under this uid, never in the
 * per-UID stats table. Real Android app/system UIDs never reach (uid_t)-1 (the
 * kernel invalid uid); on the wire this prints as 0xffffffff. Shared by both
 * kernel backends — kept here (not per-backend) so the value can never drift. */
#define VPNHIDE_GLOBAL_STATS_UID ((unsigned int)-1)

```

(Note: clang-format will render `((unsigned int) - 1)` with a space — accept its form.)

- [ ] **Step 2: remove from the .ko**

In `kmod/vpnhide_kmod.c`, delete these four lines (the define AND its 2-line comment; the define now comes from the included shared header):

```c
/* Sentinel UID for the uid-independent global prefix-hit stats row. Real
 * Android app/system UIDs never reach (uid_t)-1 (the kernel invalid uid). */
#define VPNHIDE_GLOBAL_STATS_UID ((uid_t) - 1)

```

Keep the following `/* Global (uid-independent) hook hits — … */ static u64 global_hook_counts[…]` block exactly as-is.

- [ ] **Step 3: sweep (8e6ace8 discipline) + verify**

```bash
grep -rn "VPNHIDE_GLOBAL_STATS_UID" --include="*.c" --include="*.h" --include="*.rs" --include="*.kt" .
# expect: definition ONLY in kmod/shared/vpnhide_logic.h; uses in kmod/vpnhide_kmod.c (snapshot_stats sentinel rows) — and after T2, kmod/kpm/vpnhide_kpm.c
grep -rn "0xffffffff\|0xFFFFFFFF\|4294967295\|u32::MAX" crates/protocol/src crates/activator/src lsposed/app/src/main/java 2>/dev/null | grep -iv test | head
# confirm no Rust/Kotlin DUPLICATE constant needing a value sync (the wire is value-based; expect nothing semantic to change)
"C:/Users/akash/AppData/Local/Programs/Python/Python311/Lib/site-packages/clang_format/data/bin/clang-format.exe" --style=file -i kmod/shared/vpnhide_logic.h kmod/vpnhide_kmod.c
git diff --stat   # only the two files; formatting drift confined to the new/changed lines
```

- [ ] **Step 4: commit (do NOT push — batched at T7)**

```bash
git add kmod/shared/vpnhide_logic.h kmod/vpnhide_kmod.c
git commit -m "kmod: hoist global-stats sentinel UID into the shared header"
```

---

### Task 2: KPM prefix state + ctl0 config wiring + sentinel stats

**Files:**
- Modify: `kmod/kpm/vpnhide_kpm.c`

The plumbing task: live prefix-rule state under the existing seqlock, parse `prefix` records via `vpnhide_parse_config_ex`, clear rules on the load-args path (a WRITE replaces ENTIRE state), Fix-A-style global counters, and the seqlock-consistent match helper every hook task (T3-T5) calls.

**Exact changes:**

- [ ] **Step 1: state + global counters** — after the existing stats block (the `stats_snapshot` declaration at the `/* Native interception stats, cumulative since KPM load. … */` comment), GROW the snapshot and add prefix state + sentinel counters. Replace:

```c
static struct vpnhide_stat_entry
	stats_snapshot[MAX_TARGET_UIDS * VPNHIDE_HOOK_COUNT];
```

with:

```c
/* +1 hook-row of headroom for the uid-independent global prefix-hit stats
 * (sentinel-uid rows appended after the per-uid rows at snapshot time). */
static struct vpnhide_stat_entry
	stats_snapshot[MAX_TARGET_UIDS * VPNHIDE_HOOK_COUNT +
		       VPNHIDE_HOOK_COUNT];

/* Global IPv6 prefix rules (protocol §4.3 `prefix` records). Same seqlock
 * discipline as targets[]: writers hold the cfg_writer gate with cfg_seq odd;
 * readers scan under matching even-seq reads and retry on a concurrent write. */
static struct vpnhide_prefix_rule prefix_rules[MAX_PREFIX_RULES];
static int nr_prefix_rules;

/* Global (uid-independent) hook hits — prefix-rule matches fired by non-target
 * UIDs, reported under the VPNHIDE_GLOBAL_STATS_UID sentinel row so they never
 * consume the per-UID slot table or mask a real target's stats. Atomic
 * increments only (the per-uid slot machinery is overkill for one row). */
static unsigned long long global_stats_counts[VPNHIDE_HOOK_COUNT];
```

- [ ] **Step 2: `record_global_hook_hit` + sentinel append in `snapshot_stats`**

Immediately after the existing `record_hook_hit` function, add:

```c
static void record_global_hook_hit(uint32_t hook_id)
{
	if (hook_id < VPNHIDE_HOOK_COUNT)
		__sync_fetch_and_add(&global_stats_counts[hook_id], 1ULL);
}
```

In `snapshot_stats`, at the END of the function (after the per-uid double loop, before `return n;`), append the sentinel rows (mirrors `vpnhide_kmod.c`'s snapshot_stats):

```c
	for (hook = 0; hook < VPNHIDE_HOOK_COUNT && n < max; hook++) {
		unsigned long long count = __atomic_load_n(
			&global_stats_counts[hook], __ATOMIC_RELAXED);

		if (count == 0)
			continue;
		out[n].uid = VPNHIDE_GLOBAL_STATS_UID;
		out[n].hook_id = (unsigned int)hook;
		out[n].count = count;
		n++;
	}
```

(`hook` is already declared at the top of `snapshot_stats` — reuse it, no redeclaration.)

- [ ] **Step 3: seqlock-consistent match helper** — after `iface_is_vpn`/`netdev_name` helpers (before `kpm_is_public_host_route4`), add:

```c
/* True when a prefix rule on `ifname` covers `addr` (16 bytes). Seqlock read
 * side — same pattern as hook_active: scan the live array under a consistent
 * even-seq snapshot and retry on a concurrent write. Config writes are rare,
 * so this normally makes a single pass. */
static int kpm_prefix_rule_hit(const char *ifname, const unsigned char *addr)
{
	uint32_t s1, s2;
	int hit, i;

	if (!ifname)
		return 0;
	do {
		s1 = __atomic_load_n(&cfg_seq, __ATOMIC_ACQUIRE);
		if (s1 & 1u)
			continue; /* a writer is mid-update */
		hit = 0;
		for (i = 0; i < nr_prefix_rules; i++) {
			if (vpnhide_streq(prefix_rules[i].ifname, ifname) &&
			    vpnhide_prefix_match(addr, &prefix_rules[i])) {
				hit = 1;
				break;
			}
		}
		s2 = __atomic_load_n(&cfg_seq, __ATOMIC_ACQUIRE);
	} while (s1 != s2);
	return hit;
}
```

- [ ] **Step 4: ctl0 CONFIG arm parses + publishes prefix rules** — in `vpnhide_kpm_ctl0`, replace the CONFIG arm's locals and parse/publish (OLD → NEW):

OLD:

```c
		struct vpnhide_target new_targets[MAX_TARGET_UIDS];
		int dbg = -1; /* absent debug record preserves live value */
		int i, n;

		n = vpnhide_parse_config(args, n_args, new_targets,
					 MAX_TARGET_UIDS, &dbg);
		if (n < 0)
			return -1; /* rejected whole (bad header / version) */
		if (!cfg_try_write_begin())
			return -2; /* concurrent config writer; retry from userspace */
		for (i = 0; i < n; i++)
			targets[i] = new_targets[i];
		nr_targets = n;
		active_hook_mask = compute_active_hook_mask(n);
		if (dbg >= 0)
			debug_enabled = dbg ? true : false;
		cfg_write_end();
		vpnhide_dbg("ctl0 config: %d targets, debug=%d\n", n,
			    debug_enabled ? 1 : 0);
		return 0;
```

NEW:

```c
		struct vpnhide_target new_targets[MAX_TARGET_UIDS];
		struct vpnhide_prefix_rule new_rules[MAX_PREFIX_RULES];
		int dbg = -1; /* absent debug record preserves live value */
		int i, n, nr;

		n = vpnhide_parse_config_ex(args, n_args, new_targets,
					    MAX_TARGET_UIDS, &dbg, new_rules,
					    MAX_PREFIX_RULES, &nr);
		if (n < 0)
			return -1; /* rejected whole (bad header / version) */
		if (!cfg_try_write_begin())
			return -2; /* concurrent config writer; retry from userspace */
		for (i = 0; i < n; i++)
			targets[i] = new_targets[i];
		nr_targets = n;
		for (i = 0; i < nr; i++)
			prefix_rules[i] = new_rules[i];
		nr_prefix_rules = nr;
		active_hook_mask = compute_active_hook_mask(n);
		if (dbg >= 0)
			debug_enabled = dbg ? true : false;
		cfg_write_end();
		vpnhide_dbg("ctl0 config: %d targets, %d prefix rules, debug=%d\n",
			    n, nr, debug_enabled ? 1 : 0);
		return 0;
```

- [ ] **Step 5: load-args path clears rules** — in `apply_targets`, after `active_hook_mask = compute_active_hook_mask(cnt);` and before `cfg_write_end();`, add `nr_prefix_rules = 0;` with the comment `/* a config write replaces ENTIRE state — rules too. */`. Also fix the ctl0 stats caller bound: in the `kind == VPNHIDE_KIND_STATS` arm, change `snapshot_stats(stats_snapshot, MAX_TARGET_UIDS * VPNHIDE_HOOK_COUNT)` to pass the grown bound `MAX_TARGET_UIDS * VPNHIDE_HOOK_COUNT + VPNHIDE_HOOK_COUNT`.

- [ ] **Step 6: clang-format + commit (no push)**

```bash
"C:/Users/akash/AppData/Local/Programs/Python/Python311/Lib/site-packages/clang_format/data/bin/clang-format.exe" --style=file -i kmod/kpm/vpnhide_kpm.c
git add kmod/kpm/vpnhide_kpm.c
git commit -m "kpm: parse + store global prefix rules, sentinel-uid global stats"
```

---

### Task 3: KPM `inet6_fill_ifaddr` prefix path

**Files:**
- Modify: `kmod/kpm/vpnhide_kpm.c`

Mirror of the `.ko`'s `inet6_fill_entry`: filter when (a) hook active for this uid AND iface is VPN, or (b) a prefix rule covers this address (uid-gated, independent of active); stats = "enabled" semantics via a `data3` uid_target flag (`= active`). IPv4 (`inet_fill_*`) keeps byte-identical behavior — `addr_fill_before` gains the `data3 = 1` default so the shared after-hook keeps per-uid attribution for v4.

- [ ] **Step 1: `addr_fill_before` gains the attribution default** — add as its FIRST statement:

```c
	fargs->local.data3 = 1; /* uid_target: v4 is per-uid only (no prefix path) */
```

- [ ] **Step 2: `addr_fill_after_hook` stats split** — replace `record_hook_hit(hook_id);` with:

```c
	if (fargs->local.data3)
		record_hook_hit(hook_id);
	else
		record_global_hook_hit(hook_id);
```

- [ ] **Step 3: rewrite `inet6_fill_before`** (it no longer delegates to `addr_fill_before`):

```c
static void inet6_fill_before(hook_fargs4_t *fargs, void *udata)
{
	void *dev = deref2((void *)fargs->arg1, off->inet6_ifaddr_idev,
			   off->inet6_dev_dev);
	void *skb = (void *)fargs->arg0;
	const char *name;
	int active, filter;

	fargs->local.data0 = 0;
	active = hook_active(VPNHIDE_HOOK_INET6_FILL_IFADDR);
	/* uid_target: "enabled" stats semantics (parity with the .ko's
	 * inet6_fill_data.uid_target = vpn_active) — per-uid row iff this
	 * reader is a target with the hook enabled, sentinel global row
	 * otherwise. */
	fargs->local.data3 = (uint64_t)active;
	if (!skb || !dev)
		return;
	name = netdev_name(dev);

	filter = 0;
	if (active && iface_is_vpn(name)) {
		filter = 1;
	} else if (nr_prefix_rules > 0 &&
		   vpnhide_uid_prefix_filtered((unsigned int)current_uid())) {
		/* struct inet6_ifaddr begins with struct in6_addr addr (@0) on
		 * every supported kver — the layout the .ko compiles against. */
		if (kpm_prefix_rule_hit(name, (const unsigned char *)fargs->arg1))
			filter = 1;
	}
	if (!filter)
		return;

	fargs->local.data0 = 1;
	fargs->local.data1 = (uint64_t)skb;
	fargs->local.data2 =
		(uint64_t) * (unsigned int *)((char *)skb + off->skb_len);
}
```

Note for the implementer: `nr_prefix_rules > 0` is read lock-free as a fast-path gate (mirrors the `.ko`'s `READ_ONCE(prefix_rules_present)`); the authoritative consistent read happens inside `kpm_prefix_rule_hit`. A torn fast-path read around a rare config write can only cause a one-pass over/under-filter — the same documented philosophy as the `.ko`.

- [ ] **Step 4: clang-format + commit (no push)**

```bash
"C:/Users/akash/AppData/Local/Programs/Python/Python311/Lib/site-packages/clang_format/data/bin/clang-format.exe" --style=file -i kmod/kpm/vpnhide_kpm.c
git add kmod/kpm/vpnhide_kpm.c
git commit -m "kpm: hide prefix-covered v6 addresses in inet6_fill_ifaddr (uid-gated)"
```

---

### Task 4: KPM `ipv6_route_seq_show` prefix path

**Files:**
- Modify: `kmod/kpm/vpnhide_kpm.c`

Mirror of the `.ko`'s `ipv6_route_ret` (which itself mirrors `if6_seq_ret`): uid-gated rules snapshot + shared compactor + `vpn_match` ternary + stats split. The `before` callback (`fib_route_before`, shared with `fib_route_seq_show`) is stash-only — NO change needed there.

- [ ] **Step 1: add the snapshot helper** — next to `kpm_prefix_rule_hit`, add:

```c
/* Snapshot the prefix rules under the seqlock (even-seq reads, retry on a
 * concurrent write) and return the count. Byte-wise copy: the KP build
 * environment has no guaranteed memcpy (same idiom as iface_is_vpn). */
static int kpm_snapshot_prefix_rules(struct vpnhide_prefix_rule *snap)
{
	uint32_t s1, s2;
	int n, i, j;

	do {
		s1 = __atomic_load_n(&cfg_seq, __ATOMIC_ACQUIRE);
		if (s1 & 1u)
			continue;
		n = nr_prefix_rules;
		for (i = 0; i < n; i++) {
			const char *src = (const char *)&prefix_rules[i];
			char *dst = (char *)&snap[i];

			for (j = 0; j < (int)sizeof(*snap); j++)
				dst[j] = src[j];
		}
		s2 = __atomic_load_n(&cfg_seq, __ATOMIC_ACQUIRE);
	} while (s1 != s2);
	return n;
}
```

- [ ] **Step 2: rewrite `ipv6_route_after`**:

```c
static void ipv6_route_after(hook_fargs2_t *fargs, void *udata)
{
	void *seq = (void *)fargs->arg0;
	char *buf;
	unsigned long *countp;
	unsigned long start = (unsigned long)fargs->local.data0;
	struct vpnhide_prefix_rule snap[MAX_PREFIX_RULES];
	vpnhide_match_fn vpn_match;
	int nr = 0;

	if (!seq)
		return;

	/* Same reader-uid gate as the .ko: prefix rules filter only app/shell
	 * readers; system readers (e.g. networkstack) must keep seeing real
	 * routes or network provisioning wedges (on-device finding 2026-07-18). */
	if (vpnhide_uid_prefix_filtered((unsigned int)current_uid()))
		nr = kpm_snapshot_prefix_rules(snap);

	vpn_match = hook_active(VPNHIDE_HOOK_IPV6_ROUTE_SEQ_SHOW) ?
			    iface_is_vpn :
			    (vpnhide_match_fn)0;
	if (!vpn_match && nr == 0)
		return;

	buf = *(char **)((char *)seq + off->seqfile_buf);
	countp = (unsigned long *)((char *)seq + off->seqfile_count);
	{
		unsigned long old = *countp;
		/* /proc/net/ipv6_route keeps the route destination in the FIRST
		 * field and the iface name in the LAST — the same two fields the
		 * if_inet6 compactor tokenizes, so it doubles as the route
		 * compactor (host-test-pinned in the .ko's suite). */
		unsigned long next = vpnhide_compact_if_inet6_lines(
			buf, start, old, vpn_match, snap, nr);

		*countp = next;
		if (next != old) {
			if (vpn_match)
				record_hook_hit(VPNHIDE_HOOK_IPV6_ROUTE_SEQ_SHOW);
			else
				record_global_hook_hit(
					VPNHIDE_HOOK_IPV6_ROUTE_SEQ_SHOW);
		}
	}
}
```

(`snap` = 264 B on the stack — same as the `.ko`; fine in syscall context.)

- [ ] **Step 3: clang-format + commit (no push)**

```bash
"C:/Users/akash/AppData/Local/Programs/Python/Python311/Lib/site-packages/clang_format/data/bin/clang-format.exe" --style=file -i kmod/kpm/vpnhide_kpm.c
git add kmod/kpm/vpnhide_kpm.c
git commit -m "kpm: filter ipv6_route lines by global prefix rules (uid-gated)"
```

---

### Task 5: KPM `rt6_fill_node` prefix path

**Files:**
- Modify: `kmod/kpm/vpnhide_kpm.c`

Mirror of the `.ko`'s `rt6_fill_entry` (commit 253c350 + 2eddc81 — the MERGED form, `uid_target = active`). Reuses the `kpm_is_public_host_route6` offset select for the rt6key, but reads ONLY the addr (plen never consulted).

- [ ] **Step 1: rewrite `rt6_fill_before`**:

```c
static void rt6_fill_before(hook_fargs12_t *fargs, void *udata)
{
	void *skb = (void *)fargs->arg1;
	void *rt = (void *)fargs->arg2;
	void *dev;
	int active, prefix_on, filter;

	fargs->local.data0 = 0;
	active = hook_active(VPNHIDE_HOOK_RT6_FILL_NODE);
	prefix_on = nr_prefix_rules > 0 &&
		    vpnhide_uid_prefix_filtered((unsigned int)current_uid());
	/* uid_target: "enabled" stats semantics (the .ko's rt6_fill_entry,
	 * merged form) — per-uid row iff this reader is a target with the hook
	 * enabled, sentinel global row otherwise. */
	fargs->local.data3 = (uint64_t)active;
	if ((!active && !prefix_on) || !skb || !rt)
		return;
	dev = dev_from_fib6_info(rt);
	if (!dev)
		return;

	/* Per-uid reasons, only when the hook is active for this reader: the
	 * output dev is a VPN iface, OR a public /128 host-route pinned to a
	 * physical uplink (parity with the .ko). */
	filter = 0;
	if (active && (iface_is_vpn(netdev_name(dev)) ||
		       kpm_is_public_host_route6(rt, dev)))
		filter = 1;

	/* Global prefix-rule destination: hide a route whose DESTINATION
	 * (rt6key.addr — the route's own plen is never consulted) falls inside
	 * a rule prefix on this iface. Same offset select as
	 * kpm_is_public_host_route6; a 0 offset disables the check (safe
	 * degrade on kvers with an unpopulated table entry). */
	if (!filter && prefix_on) {
		unsigned int dst_off = off->rt6_via_dst ?
					       off->rt6_dst :
					       off->fib6_info_fib6_dst;

		if (dst_off &&
		    kpm_prefix_rule_hit(netdev_name(dev),
					(const unsigned char *)rt + dst_off))
			filter = 1;
	}
	if (!filter)
		return;

	fargs->local.data0 = 1;
	fargs->local.data1 = (uint64_t)skb;
	fargs->local.data2 =
		(uint64_t) * (unsigned int *)((char *)skb + off->skb_len);
}
```

- [ ] **Step 2: `rt6_fill_after` stats split** — replace `record_hook_hit(VPNHIDE_HOOK_RT6_FILL_NODE);` with:

```c
	if (fargs->local.data3)
		record_hook_hit(VPNHIDE_HOOK_RT6_FILL_NODE);
	else
		record_global_hook_hit(VPNHIDE_HOOK_RT6_FILL_NODE);
```

- [ ] **Step 3: clang-format + commit (no push)**

```bash
"C:/Users/akash/AppData/Local/Programs/Python/Python311/Lib/site-packages/clang_format/data/bin/clang-format.exe" --style=file -i kmod/kpm/vpnhide_kpm.c
git add kmod/kpm/vpnhide_kpm.c
git commit -m "kpm: hide prefix-covered v6 route destinations in rt6_fill_node (uid-gated)"
```

---

### Task 6: docs sync (KPM prefix parity)

**Files:**
- Modify: `docs/detection-vectors.md`, `docs/diagnostics.md`, `kmod/kpm/vpnhide_kpm.c` (comments only)
- Verify-only: `docs/protocol.md`, `kmod/README.md`, `changelog.d/`

- [ ] **Step 1: `docs/detection-vectors.md` §3B paragraph** — replace the sentence `KPM and Zygisk do not implement prefix rules yet.` in the paragraph after the route table with: `KPM implements the same prefix-rule hiding on its hooked paths (v6 addresses and both route paths, uid-gated); Zygisk does not implement prefix rules yet.` — and update the opening of that paragraph (`The \`.ko\` additionally hides`) to `The kernel backends additionally hide` so the sentence no longer claims .ko-only coverage. (§3C's `if_inet6` note — KPM does NOT hook it — stays true and untouched.)

- [ ] **Step 2: `docs/diagnostics.md` §7 rows** — `netlink_getroute` note `v6: \`.ko\` also hides global prefix-rule destinations, uid-gated (KPM: VPN routes only)` → `v6: kernel backends also hide global prefix-rule destinations, uid-gated`; `proc_ipv6_route` note `\`.ko\`: VPN-iface lines + global prefix-rule destinations, uid-gated (KPM: VPN-iface lines only)` → `kernel backends: VPN-iface lines + global prefix-rule destinations, uid-gated`.

- [ ] **Step 3: KPM file comments** — in `kmod/kpm/vpnhide_kpm.c`: (a) the HOOK COVERAGE comment block: append to the `ipv6_route_seq_show`, `inet6_fill_ifaddr`, and `rt6_fill_node` entries the words `(+ global prefix rules, uid-gated)`; (b) the header DESIGN list gains a bullet: `- Global IPv6 prefix rules: parsed from ctl0 config, uid-gated (app/shell readers only), sentinel-uid global stats — parity with the .ko.` 

- [ ] **Step 4: verify-only** — read `docs/protocol.md` §4.3 (wire-level; expected: no KPM/.ko backend claims → untouched), `kmod/README.md` (`.ko`-focused hook table; the `.ko 11 / KPM 10` mask claims stay true → untouched unless a sentence claims .ko-only prefix coverage), and both `changelog.d/` prefix fragments (path-generic → untouched, no new fragment). If any DOES make a now-false claim, fix it minimally in the same commit.

- [ ] **Step 5: commit (no push)**

```bash
git add -A
git commit -m "docs: KPM prefix-rule parity on its hooked paths (uid-gated)"
```

---

### Task 7: CI gate — push + all green

- [ ] **Step 1: push the batch**

```bash
git push fork feat/ipv6-prefix-filter
```

- [ ] **Step 2: watch BOTH workflows to green** (`prefix-phase1-check.yml` + `prefix-kmod-build.yml` — the latter now with the `kpm` job from T0). Log-verify: phase1-check prints `all shared-logic tests passed` + `all 44 protocol vectors passed`; kmod-build's `kpm` job uploads `vpnhide-kpm.zip`.

- [ ] **Step 3: download the KPM artifact** (for T8's probe):

```bash
gh run download <kmod-build-run> -R awesomeblossom898-spec/vpnhide -n vpnhide-kpm -D C:/Users/akash/Desktop/PRIVACY/p5-kpm-artifact
```

---

### Task 8: on-device probe (platform-block expected) + record

**Context (verified 2026-07-19):** the Nord 3's ReSukiSU kernel has NO KernelPatch runtime — `ksud kpm num` → ENOTTY. This task honestly establishes whether anything changed, attempts the load ladder if possible, and records the outcome. **Do NOT disable the `.ko` module unless a KPM actually loads** (`.ko` + KPM together is the freeze-risk case).

- [ ] **Step 1: re-probe the platform**

```bash
adb devices -l   # d78a88ef (CPH2487)
MSYS_NO_PATHCONV=1 adb -s d78a88ef shell "su -c 'ksud kpm num; ksud kpm version'"
```

- [ ] **Step 2: if ENOTTY persists (expected)** — push the `.kpm` and attempt a load anyway (harmless if the loader is absent):

```bash
cd C:/Users/akash/Desktop/PRIVACY/p5-kpm-artifact && unzip -o vpnhide-kpm.zip vpnhide.kpm
MSYS_NO_PATHCONV=1 adb -s d78a88ef push vpnhide.kpm /sdcard/Download/
MSYS_NO_PATHCONV=1 adb -s d78a88ef shell "su -c 'ksud kpm load /sdcard/Download/vpnhide.kpm; ksud kpm list'"
```

Expected: load fails (ENOTTY / error), `ksud kpm list` empty. **If it DOES load** (kernel updated since the probe): run the adapted matrix — config via `ksud kpm control vpnhide "<config>"` (blanket rules from `/data/local/tmp/vpnhide_blanket.cfg`), shell vs root `ip -6 route table all` + `ip -6 addr` + `/proc/net/ipv6_route` probes, stats via `ksud kpm control vpnhide "vpnhide 1 stats"` (expect the `0xffffffff` row for hooks 0x1/0x4/0x8 after shell probes), `svc data` toggle validation timing, dmesg window for zero system-uid filter lines — then `ksud kpm unload vpnhide`. `/proc/net/if_inet6` is EXPECTED TO LEAK on KPM (no if6_seq_show — documented, not a failure).

- [ ] **Step 3: record** the outcome (loaded-matrix OR platform-block evidence) in `.superpowers/sdd/progress.md`, and note the block + the unlock condition (KPM-capable kernel: KernelSU-Next with KPM / APatch / KPatch-Next-Module on the burner — a user decision, NOT autonomous) in the handoff. Device stays on the `.ko` (`v1.1.1-55-g9fc2e57`, 8 prefix rules) — healthy end state unchanged.

---

## Self-review notes (already applied)

- Spec coverage: design §12 Phase-5 row = "KPM parity … reuses the shared parser; add match calls in its inline hooks; mirror the Fix-A global-counter split" → T2 (parser + stats) + T3/T4/T5 (match calls) cover it; "status/mask plumbing already correct" → verified untouched.
- No placeholders: every code step has the full code.
- Type consistency: `kpm_prefix_rule_hit(name, addr16)` used identically in T3/T5; `kpm_snapshot_prefix_rules` only in T4; `data3` = uid_target flag on `addr_fill_*`/`rt6_fill_*` only (other hooks never touch `local.data3` — fib_route/ipv6_route use hook_fargs2_t whose locals go up to data1? VERIFY: hook_fargs2_t local has data0..dataN — ipv6_route_after uses only data0 (start). The seq hooks record via vpn_match ternary, NOT data3 — consistent with the plan).
- Attribution pitfall (from Phase 4 quality Minor 1): `uid_target = active` everywhere — NOT "which reason fired". Carried into T3/T5 verbatim.
- memcpy pitfall: byte-loop only (fact 10).
- Plan amendment pitfall (from Phase 4 final review): this plan IS the amended source of truth for the stats semantics.
