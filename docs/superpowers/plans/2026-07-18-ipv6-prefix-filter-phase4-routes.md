# IPv6 Prefix Filter — Phase 4 (v6 route hooks) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the global IPv6 prefix filter to the two v6 route paths — `rt6_fill_node` (netlink RTM_GETROUTE v6) and `ipv6_route_seq_show` (`/proc/net/ipv6_route`) — closing the `ip -6 route` /64 leak, and pin the prefix-line-before-target config ordering with a golden vector.

**Architecture:** Same pattern Phase 2/T8 established for addresses, applied to route destinations: (1) the procfs path reuses the freestanding `vpnhide_compact_if_inet6_lines` compactor — `/proc/net/ipv6_route` lines keep the route destination in the FIRST field and the iface name in the LAST field, the same two fields the compactor tokenizes; (2) the netlink path reuses `prefix_rule_hits(dev_name, addr)` on `rt->fib6_dst.addr` (the `.ko` already reads `fib6_dst` via compile-time member access — no offset table, no new offsets); (3) BOTH paths reuse the T8 reader-uid gate (`vpnhide_uid_prefix_filtered`) — networkstack (uid 1073) reads route dumps during provisioning and must see truth; (4) stats follow the Fix-A split: per-uid reasons (`vpn_route`/`host_hint`/vpn_match) attribute via `record_hook_hit`, global-only prefix filtering via `record_global_hook_hit` (sentinel uid `0xFFFFFFFF`).

**Tech Stack:** kernel `.ko` C (`kmod/vpnhide_kmod.c`, freestanding shared logic in `kmod/shared/vpnhide_logic.h`), host C tests (`kmod/shared/test_vpnhide_logic.c`), golden vectors (`kmod/shared/protocol_vectors.tsv`, consumed byte-exact by C + Rust + Kotlin tests).

**Scope boundary (do not cross):** IPv4 paths (`fib_dump_info`, `fib_route_seq_show`) untouched — no IPv4 filtering ever. KPM untouched (Phase 5). Zygisk untouched (Phase 6). No new hook ids (behavior of existing hooks 1 + 8 extends; masks unchanged). Per-uid VPN-route hiding semantics byte-identical. No changelog fragment (unreleased-feature extension; the phase's `added` fragments already cover the feature — Task 5 verifies the fragment wording is path-generic).

**Key verified facts the tasks rely on (research 2026-07-18):**
- `vpnhide_compact_if_inet6_lines` (`kmod/shared/vpnhide_logic.h:635`) tokenizes only first-field-addr32 + last-field-ifname; intermediate field count is irrelevant → mechanically correct on 10-field `ipv6_route` lines. The route's own plen (2nd field) is never read; rule semantics: hide a line when `streq(ifname, rule.ifname) && vpnhide_prefix_match(dst_addr, rule)` — the route destination falls inside the rule prefix. Default routes (`::/0` dst), `fe80::/10` link routes, and `ff00::/8` multicast routes never match a global-prefix rule → kept (correct: they don't leak the prefix).
- `rt6_fill_entry` (`kmod/vpnhide_kmod.c:1418`) already resolves `dev_name` under `rcu_read_lock()`; `is_public_host_route6_via_physical` (`:1213`) already reads `rt->fib6_dst.{plen,addr}` fault-safe — mirror that access pattern for the prefix match.
- `struct route_skb_data` (`:1325`) is shared by fib_dump/rt6/fib_rule; `init_route_skb_data` (`:1331`) is the single init point.
- `if6_seq_entry`/`if6_seq_ret` (`:1104-1164`) are the exact uid-gate + snapshot + stats-split mirror for the new `ipv6_route_entry`/`ipv6_route_ret`.
- Kernel C is `-Werror` + no-declaration-after-statement (declarations at block starts only). clang-format **18** before push; never reformat `kmod/generated/`.
- CI gates: `prefix-phase1-check.yml` (host C tests + Rust/Kotlin golden vectors) and `prefix-kmod-build.yml` (both KMIs compile). QEMU does not run on the fork → on-device (Nord 3) is the runtime gate.

---

### Task 1: Golden vector — valid `prefix` line BEFORE a `target` line (final-review minor 1)

All three parsers (C `vpnhide_parse_config_ex` `vpnhide_logic.h:799`, Rust `crates/protocol/src/lib.rs:286`, Kotlin `Protocol.kt:174`) are order-independent by construction (separate target/prefix collections; producers emit targets first). This locks the guarantee with one vector consumed byte-exact by all three test suites.

**Files:**
- Modify: `kmod/shared/protocol_vectors.tsv` (append after the existing 8 prefix vectors, currently ending at line 102)

- [ ] **Step 1: Append the vector row**

```
cfg|vpnhide 1 config\nprefix wlan0 fe800000000000000000000000000000 0x40\ntarget 0x2710 0x1\n|debug=-1;0x2710:0x1;pfx:wlan0:fe800000000000000000000000000000:64
```

Expected-output rationale: C `run_cfg` renders targets from `out[]` then prefixes from `pout[]`; Rust/Kotlin `format*` emit targets-then-prefixes — so all three produce `debug=-1;0x2710:0x1;pfx:...` regardless of input order. The `count >= 30` assertions (Rust `lib.rs:582`, Kotlin `ProtocolTest.kt:169`) keep passing (we add, not remove).

- [ ] **Step 2: Commit**

```bash
git add kmod/shared/protocol_vectors.tsv
git commit -m "test: pin prefix-before-target config ordering with a golden vector"
```

(CI verification batched in Task 6 — the C host runner, Rust `golden_vectors`, and Kotlin `goldenVectors` all read this file.)

---

### Task 2: Host test — `ipv6_route` line compaction under prefix rules

Pins the procfs-side semantics Task 3 wires into the kernel: a route line drops iff its destination (first field) falls inside a rule prefix on that iface (last field); link-local/multicast/other-iface/other-prefix lines stay; no-trailing-newline tail handled. NOTE: the compactor already handles these lines mechanically (Phase 2 built it field-agnostic) — this test PINS the semantics, it is not expected to fail first; the kernel-side wiring (Task 3) is what it protects against regression.

**Files:**
- Modify: `kmod/shared/test_vpnhide_logic.c` (new test after `test_compact_if_inet6_vpn_and_edges` ending `:321`; register in `main()` at `:335`)

- [ ] **Step 1: Add the test**

```c
static void test_compact_ipv6_route_prefix(void)
{
	/* /proc/net/ipv6_route: "<dst32> <plen> <src32> <srcplen> <nh32>
	 * <metric> <ref> <use> <flags> <name>" — the compactor reads only the
	 * FIRST (dst) and LAST (ifname) fields, exactly like if_inet6. */
	char buf[640] =
		"24014900a3f1e04d0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"24014900a41fb57c0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data3\n"
		"ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"24014900a3f1e04d54fdd7fffeb173bf 80 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1";
	/* rule: hide 2401:4900::/32 on rmnet_data1 only */
	struct vpnhide_prefix_rule rules[1];
	unsigned long n;

	memset(&rules[0], 0, sizeof(rules[0]));
	strcpy(rules[0].ifname, "rmnet_data1");
	rules[0].addr[0] = 0x24;
	rules[0].addr[1] = 0x01;
	rules[0].addr[2] = 0x49;
	rules[0].addr[3] = 0x00;
	rules[0].prefix_len = 32;

	/* vpn_match NULL -> only prefix rules fire: the rmnet_data1 /64 subnet
	 * route and the /128 host route inside 2401:4900::/32 go; the fe80
	 * link route (outside the rule), the rmnet_data3 /64 (other iface),
	 * and the ff00::/8 multicast route (outside the rule) stay; the
	 * no-trailing-newline tail is preserved by the down-only copy. */
	n = vpnhide_compact_if_inet6_lines(buf, 0, strlen(buf),
					   (vpnhide_match_fn)0, rules, 1);
	buf[n] = '\0';
	expect_str(
		"ipv6_route: prefix-dest routes removed, link/mcast/other-iface kept",
		buf,
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n"
		"24014900a41fb57c0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data3\n"
		"ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 100 0 0 1 rmnet_data1\n");
}
```

Register in `main()` after `test_compact_if_inet6_vpn_and_edges();`:

```c
	test_compact_ipv6_route_prefix();
```

(`strcpy` of the ifname mirrors `test_compact_if_inet6_vpn_and_edges:288`; `expect_str` is defined at `:86`.)

- [ ] **Step 2: Commit**

```bash
git add kmod/shared/test_vpnhide_logic.c
git commit -m "test: pin ipv6_route prefix-destination compaction semantics"
```

(CI runs the host suite in Task 6.)

---

### Task 3: `.ko` — `ipv6_route_seq_show` prefix wiring

Mirror of `if6_seq_entry`/`if6_seq_ret` (`vpnhide_kmod.c:1104-1164`): entry runs the return path when per-uid VPN hiding is active OR any prefix rule exists; return snapshots rules under `targets_lock` only for app/shell readers, compacts first-field-dest/last-field-ifname lines, and splits stats per mechanism.

**Files:**
- Modify: `kmod/vpnhide_kmod.c` (`ipv6_route_entry` `:1047-1063`, `ipv6_route_ret` `:1065-1087`, section comment `:1040-1045`)

- [ ] **Step 1: Replace the entry gate (one line)**

In `ipv6_route_entry`, replace

```c
	data->target = hook_active(VPNHIDE_HOOK_IPV6_ROUTE_SEQ_SHOW);
```

with

```c
	data->target = hook_active(VPNHIDE_HOOK_IPV6_ROUTE_SEQ_SHOW) ||
		       READ_ONCE(prefix_rules_present);
```

- [ ] **Step 2: Replace `ipv6_route_ret` wholesale**

```c
static int ipv6_route_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct fib_route_data *data = (void *)ri->data;
	struct seq_file *seq = data->seq;
	struct vpnhide_prefix_rule snap[MAX_PREFIX_RULES];
	vpnhide_match_fn vpn_match;
	unsigned long newc;
	int np;

	if (!data->target || !seq || !seq->buf)
		return 0;
	if (seq->count <= data->start_count)
		return 0;

	/* Same reader-uid gate as if6_seq_ret: prefix rules filter only
	 * app/shell readers; system readers (e.g. networkstack) must keep
	 * seeing real routes or network provisioning wedges (on-device
	 * finding 2026-07-18). For other readers pass no rules (np = 0). */
	if (vpnhide_uid_prefix_filtered(
		    from_kuid(&init_user_ns, current_uid()))) {
		/* Snapshot prefix rules under the lock; the compactor is
		 * freestanding and must not take kernel locks itself. */
		spin_lock(&targets_lock);
		np = nr_prefix_rules;
		memcpy(snap, prefix_rules, (size_t)np * sizeof(*snap));
		spin_unlock(&targets_lock);
	} else {
		np = 0;
	}

	/* /proc/net/ipv6_route keeps the route destination in the FIRST
	 * field and the iface name in the LAST — the same two fields the
	 * if_inet6 compactor tokenizes, so it doubles as the route
	 * compactor: a line drops when the per-uid vpn_match fires on the
	 * iface or a global prefix rule covers the route destination. */
	vpn_match = hook_active(VPNHIDE_HOOK_IPV6_ROUTE_SEQ_SHOW) ?
			    vpnhide_iface_is_vpn :
			    (vpnhide_match_fn)0;

	newc = vpnhide_compact_if_inet6_lines(seq->buf, data->start_count,
					      seq->count, vpn_match, snap, np);
	if (newc != seq->count) {
		seq->count = newc;
		if (vpn_match)
			record_hook_hit(VPNHIDE_HOOK_IPV6_ROUTE_SEQ_SHOW);
		else
			record_global_hook_hit(VPNHIDE_HOOK_IPV6_ROUTE_SEQ_SHOW);
	}
	return 0;
}
```

- [ ] **Step 3: Update the section comment (`:1040-1045`)**

```c
/* ================================================================== */
/*  Hook 7: ipv6_route_seq_show — /proc/net/ipv6_route                */
/*                                                                    */
/*  IPv6 route lines store the route destination in the first field   */
/*  and the interface name in the last. We compact out lines that a   */
/*  VPN-iface match (per-uid) or a global prefix rule covers,         */
/*  mirroring the if6_seq strategy.                                   */
/* ================================================================== */
```

- [ ] **Step 4: clang-format 18 the file, then commit**

```bash
<clang-format-18> -i kmod/vpnhide_kmod.c   # style=file; never touch kmod/generated/
git add kmod/vpnhide_kmod.c
git commit -m "kmod: filter ipv6_route lines by global prefix rules (uid-gated)"
```

---

### Task 4: `.ko` — `rt6_fill_node` prefix path (netlink RTM_GETROUTE v6)

Adds the global prefix match to the rt6 entry decision and splits the stats attribution in the shared `route_skb_ret`. `struct route_skb_data` gains a `uid_target` flag (same convention as `inet6_fill_data.uid_target` at `:819-824`): fib_dump/fib_rule keep per-uid attribution via the init default; rt6 sets it false when ONLY a prefix rule fired.

**Files:**
- Modify: `kmod/vpnhide_kmod.c` (`struct route_skb_data` `:1325-1329`, `init_route_skb_data` `:1331-1336`, `route_skb_ret` `:1338-1352`, `rt6_fill_entry` `:1418-1453`)

- [ ] **Step 1: Extend the data struct + init**

Replace `struct route_skb_data` with:

```c
struct route_skb_data {
	struct sk_buff *skb;
	unsigned int saved_len;
	bool should_filter;
	bool uid_target; /* per-uid reason fired; false = global prefix only */
};
```

Replace `init_route_skb_data` with (fib_dump/fib_rule are per-uid only, so the default is `true`; rt6 overrides):

```c
static void init_route_skb_data(struct route_skb_data *data)
{
	data->skb = NULL;
	data->saved_len = 0;
	data->should_filter = false;
	data->uid_target = true;
}
```

- [ ] **Step 2: Split the stats attribution in `route_skb_ret`**

Replace the `if (regs_return_value(regs) >= 0)` block body with:

```c
	if (regs_return_value(regs) >= 0) {
		vpnhide_dbg("%s: trimming skb %u -> %u\n", hook_name,
			    data->skb->len, data->saved_len);
		skb_trim(data->skb, data->saved_len);
		regs_set_return_value(regs, 0);
		if (data->uid_target)
			record_hook_hit(hook_id);
		else
			record_global_hook_hit(hook_id);
	}
```

- [ ] **Step 3: Replace `rt6_fill_entry` wholesale**

```c
static int rt6_fill_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct route_skb_data *data = (void *)ri->data;
	struct fib6_info *rt = (struct fib6_info *)regs->regs[2];
	struct dst_entry *dst = (struct dst_entry *)regs->regs[3];
	struct net_device *dev = NULL;
	char dev_name[IFNAMSIZ];
	unsigned int uid = from_kuid(&init_user_ns, current_uid());
	bool active = hook_active(VPNHIDE_HOOK_RT6_FILL_NODE);
	bool prefix_on = READ_ONCE(prefix_rules_present) &&
			 vpnhide_uid_prefix_filtered(uid);

	init_route_skb_data(data);

	if (!active && !prefix_on)
		return 0;

	rcu_read_lock();
	dev = dev_from_fib6_info(rt);
	if (!dev && dst)
		copy_from_kernel_nofault(&dev, &dst->dev, sizeof(dev));
	if (copy_dev_name(dev, dev_name)) {
		bool vpn_route = active && is_vpn_ifname(dev_name);
		bool host_hint = active && !vpn_route &&
				 is_public_host_route6_via_physical(rt, dev);
		bool prefix_hit = false;

		if (prefix_on && !vpn_route) {
			struct in6_addr dst_addr;

			/* fib6_dst (rt6key { addr; plen }) is stable across
			 * GKI 5.10..6.12; fault-safe read, mirroring
			 * is_public_host_route6_via_physical. A route whose
			 * destination falls inside a rule prefix on this
			 * iface leaks that prefix (e.g. the RA /64) — hide
			 * it for app/shell readers. */
			if (!copy_from_kernel_nofault(&dst_addr,
						      &rt->fib6_dst.addr,
						      sizeof(dst_addr)))
				prefix_hit = prefix_rule_hits(dev_name,
							      dst_addr.s6_addr);
		}

		if (vpn_route || host_hint || prefix_hit) {
			data->skb = (struct sk_buff *)regs->regs[1];
			data->saved_len = data->skb ? data->skb->len : 0;
			data->should_filter = true;
			data->uid_target = vpn_route || host_hint;
			vpnhide_dbg("rt6_fill_entry: hiding %s via %s\n",
				    vpn_route ? "VPN route" :
						(host_hint ? "public host route" :
							     "prefix rule"),
				    dev_name);
		}
	}
	rcu_read_unlock();

	return 0;
}
```

Notes for the implementer (verified, do not re-derive): `prefix_rule_hits` (`:171`) takes `targets_lock` internally — safe under `rcu_read_lock` (no sleep; same pattern as `inet6_fill_entry`). The `vpn_route`/`host_hint` terms are gated on `active` so a non-target reader with prefix rules never triggers per-uid hiding (semantics byte-identical for target readers). `struct in6_addr dst_addr;` sits at the start of its block (no-declaration-after-statement). `fib_dump_entry`/`fib_rule_entry` are untouched — the init default preserves their `record_hook_hit` behavior.

- [ ] **Step 4: clang-format 18 the file, then commit**

```bash
<clang-format-18> -i kmod/vpnhide_kmod.c
git add kmod/vpnhide_kmod.c
git commit -m "kmod: hide prefix-covered v6 route destinations in rt6_fill_node (uid-gated)"
```

---

### Task 5: Docs sync (prefix-record semantics now cover route destinations)

- [ ] **Step 1: `docs/protocol.md` §4.3** — in the `prefix` record bullet, extend the semantics sentence: the rule hides not only matching v6 ADDRESSES but also matching ROUTE DESTINATIONS on that iface — in `if_inet6`/RTM_GETADDR (Phase 2) and in `/proc/net/ipv6_route`/RTM_GETROUTE v6 (this phase), under the same reader-uid gate. One sentence, existing style; do not restructure.
- [ ] **Step 2: `kmod/README.md` hook table** — extend two rows minimally: `ipv6_route_seq_show` (adds "and global prefix-rule route destinations") and `rt6_fill_node` (same). Keep the `.ko 11 / KPM 10` split claims intact (no new hooks).
- [ ] **Step 3: `docs/detection-vectors.md`** — the `ipv6_route`/`netlink getroute v6` rows: the kmod cell gains prefix-destination coverage; if a known-gap line still lists the route-path /64 leak, remove that item (now covered; tcp/tcp6 remain the gap).
- [ ] **Step 4: `docs/diagnostics.md` §7** — `proc_ipv6_route` and `netlink_getroute` rows: note column gains "prefix destinations uid-gated".
- [ ] **Step 5: `changelog.d/` check** — read the pending prefix-filter fragment(s); if the text enumerates covered paths (e.g. "address enumeration"), amend to include route destinations; if it is path-generic ("global IPv6 prefix rules"), leave untouched. No NEW fragment (unreleased-feature extension).
- [ ] **Step 6: Commit**

```bash
git commit -m "docs: prefix rules now cover v6 route destinations (uid-gated)"
```

---

### Task 6: CI gate (batch push)

- [ ] **Step 1: Push the task chain to `fork`**

```bash
git push fork feat/ipv6-prefix-filter
```

- [ ] **Step 2: Watch both workflows to GREEN**

```bash
gh run list -R awesomeblossom898-spec/vpnhide --branch feat/ipv6-prefix-filter --limit 4
gh run watch <prefix-kmod-build-run> -R awesomeblossom898-spec/vpnhide --exit-status
gh run watch <prefix-phase1-check-run> -R awesomeblossom898-spec/vpnhide --exit-status
```

Expected: phase1-check runs the host C suite (incl. `test_compact_ipv6_route_prefix` + the new tsv vector through C/Rust/Kotlin) and both KMIs compile with `-Werror`. Any red → root-cause, fix once, re-run.

---

### Task 7: On-device verification (Nord 3, adb)

New module build from the Task-6 HEAD → install → reboot → acceptance matrix. The device keeps the T8 blanket-rule state (runtime cfg at `/data/local/tmp/vpnhide_blanket.cfg`; rules cover the internet /32 on rmnet_data0-3).

- [ ] **Step 1: Build + install**

Download `vpnhide-kmod-android12-5.10` from the Task-6 kmod-build run; `adb push` to `/sdcard/Download/`; install via `ksud module install`; reboot; confirm boot-load (dmesg: 11 kretprobes registered; boot activator config applied).

- [ ] **Step 2: Re-apply blanket rules** (runtime; canonical JSON has no rules yet — Phase 7 writes those):

```bash
adb shell "su -c 'cat /data/local/tmp/vpnhide_blanket.cfg > /proc/vpnhide_ctl'"
```

Confirm via dmesg: `config applied — 0 targets, 4 prefix rules`.

- [ ] **Step 3: Acceptance matrix (all MUST pass)**

| # | Check | Expected |
|---|---|---|
| 1 | shell `ip -6 route show` | the internet /64 subnet route on the covered rmnet_dataN GONE; `default`/`fe80::/64` routes PRESENT |
| 2 | shell `cat /proc/net/ipv6_route` | covered /64 dst lines GONE; IMS /32 lines PRESENT; `fe80` lines PRESENT |
| 3 | root control: rows 1-2 as `su 0` | everything PRESENT (unfiltered) |
| 4 | `svc data disable && svc data enable` | mobile data validates fast (<5s) — networkstack reads routes unfiltered (uid 1073) |
| 5 | sentinel stats before/after shell probes | `0xffffffff` counters for hook `0x1` (ipv6_route_seq_show) and `0x8` (rt6_fill_node) increment |
| 6 | `dumpsys connectivity` | internet + IMS VALIDATED + NOT_VPN |
| 7 | dmesg during bring-up | ZERO prefix filter lines for system uids |
| 8 | T8 address-path rows (spot re-check) | shell `ip -6 addr`/`cat /proc/net/if_inet6` still filtered; IPv4 untouched |

- [ ] **Step 4: Record the matrix + evidence in `.superpowers/sdd/progress.md`; device left healthy with rules applied.**

---

## Self-review notes (orchestrator, pre-execution)

- **Spec coverage:** design spec §12 item 4 (route hooks) → Tasks 3+4+7; final-review minor 1 (ordering vector) → Task 1; uid-gate mandatory reuse → Tasks 3+4 (both mirror T8); stats Fix-A split → Tasks 3 (vpn_match split) + 4 (uid_target split); docs truthfulness → Task 5; verification discipline → Tasks 6+7.
- **No placeholders:** every code step shows complete code; every command is exact; anchors verified against `bcb3af9`.
- **Type consistency:** `vpnhide_compact_if_inet6_lines(char *, unsigned long, unsigned long, vpnhide_match_fn, const struct vpnhide_prefix_rule *, int)`; `prefix_rule_hits(const char *, const unsigned char[16])`; `vpnhide_uid_prefix_filtered(unsigned int)`; `route_skb_data` field `uid_target` used consistently across init/rt6/ret.
- **Known non-goals restated:** KPM/Zygisk parity (Phases 5/6); IPv4 never; no new hook ids; host tests can't cover kernel hook bodies (on-device is the behavioral gate, same as Phase 2).
