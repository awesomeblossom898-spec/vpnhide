# Phase 8 — Polish Minors Close-out (PRIVATE project, NO upstream PR) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Burn down every carried review minor from Phases 2–7 so the fork is fully clean — no upstream PR (user decision 2026-07-19: completely private project).

**Architecture:** Three independent batches (kmod C comments/docs, zygisk Rust parity/perf, LSPosed Kotlin UI/tests), each implemented by a fresh subagent, orchestrator-verified, spec+quality reviewed, gated, pushed, CI-watched. One final on-device spot verification for the surfaces that change behavior (zygisk module + APK).

**Tech Stack:** C (kretprobe kmod, -Werror, clang-format 18.x only), Rust (zygisk filter/hooks), Kotlin Compose (LSPosed app), fork CI (`prefix-phase1-check.yml`, `prefix-kmod-build.yml`).

**Hard constraints (all standing):** NEVER push to `origin`; repo-local git identity (vpnhide-prefix / vpnhide-prefix@localhost); no `#NN` in commit messages; no AI-tool mentions in commits; clang-format MUST be 18.x; never reformat `kmod/generated/`; do NOT bump VERSION / run release.py; changelog fragment required ONLY for user-visible changes (Batch C items 1+2 qualify — one fragment covering both; comment/docs/test-only batches skip it); StatisticsScreen.kt ≤1102 lines (at 1101); SettingsScreen.kt ≤1201 (at 1193); ktlint 1.8.0 at `/tmp/ktlint`; detekt maxIssues:0; lint UnusedResources=error; strings bilingual en+ru.

---

## Dispositions already locked (do NOT implement)

- **T2 section-ordering observation** — reviewer said "not genuinely wrong… Minor observation, not a change request"; adjudicated LEAVE (churn cost). Record in ledger only.
- **P6 T8 minors m2–m5** (stage-1 find_map, EINTR/RCVTIMEO, whole-dump abort, address-join renumbering) — adjudicated ACCEPT in P6 T8-FINAL. Not carried.
- **P2 minor (a)** — already fixed by Fix-B (`66f3772`). P2 IMPORTANT (stats table exhaustion) — already fixed by Fix-A (`7d98d6b`).

## Batch A — kmod C comment/docs polish (task #63)

**Files:**
- Modify: `kmod/vpnhide_kmod.c` (banners ~1036–1041, ~1120–1124; `prefix_rule_hits` ~:171; sentinel definition site)
- Modify: host test file containing Fix-B Case B comment (`kmod/tests/` — locate via `grep -rn "even a VPN line" kmod/`)
- Modify: `kmod/README.md:14` (`inet6_fill_ifaddr` table row)

All items are comment/docs-only EXCEPT A3 which is verify-first (likely already fixed).

- [ ] **A1 — banner labels + circular mirror refs.** Current state: `vpnhide_kmod.c:1036` banner `/* Hook 7: ipv6_route_seq_show …` says "mirroring the if6_seq strategy" (:1041); `:1120` banner `/* Hook 11: if6_seq_show …` says "mirroring the ipv6_route strategy" (:1124) — circular, and the ordinal labels (7, 11) don't match generated hook ids (ipv6_route_seq_show = id 1, if6_seq_show = id 25, per `kmod/generated/hook_ids.h` — never edit that file). Fix: each banner names its generated hook id and states precisely WHAT it mirrors from the other (compaction strategy vs prefix-filter strategy), breaking the circle; also fix the P2(c) complaint that the "Hook 11" section physically sits between sections 7 and 8 if that is still the layout (check all `Hook N:` banner ordinals in the file for monotonic order; renumber labels ONLY, do not move code).
- [ ] **A2 — prefix_rule_hits lock note.** At `vpnhide_kmod.c:171` (`static bool prefix_rule_hits(...)`): add a short comment noting the accepted tradeoff (P2 minor b): takes `targets_lock` for ALL reader uids whenever ≥1 rule is set; acceptable because the critical section is a ≤8-iteration byte compare and contention is bounded by seq/netlink read concurrency.
- [ ] **A3 — inet6_fill_entry dbg uid.** Verify-first: `vpnhide_kmod.c:854` currently prints `"inet6_fill_entry: iface=%s uid=%u -> filter\n"` — uid IS present (P2 minor d appears already fixed by the t8 print extension). If verified present: NO change; record verification in the report. Only if a sibling print in the same function still lacks uid where the minor said "dropped", restore it there.
- [ ] **A4 — Fix-B Case B comment literal.** Locate `grep -rn "even a VPN line" kmod/` — the comment over-claims (the pre-start line is rmnet_data1, not a VPN iface). Swap the comment wording to name `tun0` (or reword to "even a covered/VPN line" only if the test data actually uses tun0 — implementer must read the test and make the comment literally true).
- [ ] **A5 — sentinel aliasing note.** Near the `VPNHIDE_GLOBAL_STATS_UID` definition: add a one-two line comment noting the theoretical aliasing with child-userns unmapped uids (from_kuid property) and that it is unreachable on Android (P2 minor f, accepted).
- [ ] **A6 — README inet6 row.** `kmod/README.md:14`: the `inet6_fill_ifaddr` row says only "Trims VPN entries from RTM_GETADDR IPv6 responses" — imprecise since P2: it also trims addresses covered by global prefix rules. Mirror the precision of the `ipv6_route_seq_show` row two lines below ("VPN-interface and global prefix-rule …"). v4 row (`inet_fill_ifaddr`) must NOT change (prefix filter is v6-only).
- [ ] **Gates:** clang-format 18.1.8 check on changed C files (`clang-format --dry-run --Werror` semantics — comments re-wrapped must stay within the file's existing banner style, 80-col); `git diff` sanity (comment/docs only, zero functional lines); commit + push + watch both CI workflows green.

## Batch B — zygisk Rust parity/perf (task #64)

**Files:**
- Modify: `zygisk/src/filter.rs` (`first_field_addr_hit` :224, `extract_last_field` :240)
- Modify: `zygisk/src/hooks.rs` (`hooked_recvmsg` :836, unconditional `resolve_prefix_rules()` at :874)
- Test: host tests in the same files' `#[cfg(test)]` modules

- [ ] **B1 — procfs helper C parity (P6 M2).** Divergences vs the C helpers (`kmod/vpnhide_kmod.c`): (a) `first_field_addr_hit` — C skips leading whitespace before the first field; Rust must match. (b) `extract_last_field` — C trims a trailing `\r`; Rust must match. Kernel procfs never emits leading ws or `\r` so this is unreachable in production — fix anyway for bit-exact parity discipline. Implementer MUST first read the C versions and transcribe semantics exactly, then add host unit tests: leading-ws lines, `\r\n`-terminated lines, and equivalence cases proving identical accept/reject on kernel-shaped input.
- [ ] **B2 — recvmsg resolve gating (P6 M4/m1).** `hooked_recvmsg` calls `resolve_prefix_rules()` unconditionally (:874) before knowing whether the received message is a netlink dump it filters. Cost: ≤8 ioctls per dump only when rules are configured; zero-syscall when empty (accepted direction). Fix IF structurally safe: defer resolution until after the message-family/type check passes (RTM_NEWADDR/RTM_NEWROUTE path), mirroring the guard shape already used at :1035. The IN_GETIFADDRS recursion guard semantics must be preserved exactly; if the reorder cannot be made provably equivalent, implementer adds a justify-comment at :874 instead and reports why.
- [ ] **Gates:** host `cargo fmt --check` + `cargo test -p vpnhide_zygisk` unavailable locally (no host cargo) → pre-push derisk: transcribe changed fns into a standalone probe file and host-clippy via CI only; push early, watch `prefix-phase1-check` (host fmt+test) + `prefix-kmod-build` (android clippy + module zip). Download `vpnhide-zygisk` artifact for on-device.
- [ ] **On-device spot verify:** swap module zip on Nord 3 (keep version), `killall zygote64 zygote`, re-run nlprobe rows 1 (GAI covered=0), 4 (netlink msgs=10/46 covered=0), 6 (v4 untouched) — the P6 harness `dev.vpnhide.nlprobe` is still installed. Blanket config unchanged (8 rules live).

## Batch C — LSPosed Kotlin polish (task #65)

**Files:**
- Modify: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/PrefixRulesSettingsScreen.kt` (spinner branch ~:136-144; remove button ~:243-245)
- Modify: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/StatisticsScreen.kt` (appLabel :982-986 — extraction target; MUST stay ≤1102)
- Modify: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/ProbeStats.kt` (home of SENTINEL_UID — extraction destination)
- Modify: `lsposed/app/src/main/res/values/strings.xml` + `values-ru/strings.xml`
- Test: `lsposed/app/src/test/kotlin/dev/okhsunrog/vpnhint/` (new JVM test)

- [ ] **C1 — spinner-stranding (T1 minor).** If `refreshAfterSave` fails, `_error` is set but `_value` stays null and the `canonical == null` branch (:136-144) shows the spinner forever with the draft already wiped. Fix: mirror the existing error/retry pattern (`TargetPickerScaffold.kt:189-198` TargetsLoadErrorCard; `HiddenAppsSettingsScreen.kt:250-258`) — show an error card with Retry when value==null && error!=null. Read both reference implementations and reuse the load-bearing idiom; do not invent a new one.
- [ ] **C2 — TalkBack remove label (T1 minor).** Every row's IconButton announces the same "Remove rule"; with up to 8 rows TalkBack users can't distinguish them. Parameterize: `stringResource(R.string.prefix_rule_remove_n, index + 1)` → en "Remove rule %1$d", ru "Удалить правило %1$d" (verify ru wording against existing ru strings' style). Keep `prefix_rule_remove` if referenced elsewhere; delete only if orphaned (lint UnusedResources=error).
- [ ] **C3 — sentinel label unit test (T3 deferred minor).** StatisticsScreen.kt is at 1101/1102 — extraction must be budget-neutral. Move the label DECISION out of the composable: add to ProbeStats.kt a pure function, e.g. `internal fun statsAppLabel(uid: Long, packageNames: List<String>, globalLabel: String, unknownLabel: (Long) -> String): String` implementing: sentinel → globalLabel; packages non-empty → joined; else unknownLabel(uid). `appLabel` composable becomes a 3-line delegator (net-negative line count). New JVM test `ProbeStatsTest.kt` (or extend existing): sentinel-uid case, empty-packages non-sentinel case, multi-package join case.
- [ ] **Changelog:** ONE fragment via `./scripts/changelog.py fixed "<EN>" "<RU>"` covering C1+C2 (user-visible); C3 is test-only (no fragment).
- [ ] **Gates:** pinned ktlint 1.8.0 direct (`/tmp/ktlint`), detekt, lint, `testDebugUnitTest` (fresh execution, no cache), assembleRelease; install APK on Nord 3; on-device spot verify: Statistics still renders "Global (not one app)"; editor renders 8/8 blanket; TalkBack string present in dump (content-desc "Remove rule 1" on first card).

## Final (task #66)

- [ ] Full gate sweep re-run after all batches merge on HEAD.
- [ ] Push all; watch BOTH workflows green on final HEAD.
- [ ] On-device verification summary for changed surfaces (B: nlprobe rows; C: UI screenshots).
- [ ] OP15/Jio confirm ONLY if the second device appears in `adb devices`; otherwise record as not-available.
- [ ] Ledger append `## PHASE 8` to `.superpowers/sdd/progress.md`; refresh handoff (status dashboard, commit ledger, CI runs, closing line "PROJECT COMPLETE").

## Self-review notes

- Spec coverage: every carried minor from progress.md/handoff maps to exactly one batch item or a locked disposition above. P2: a(fixB-done) b(A2) c(A1) d(A3-verify) e(A4) f(A5). P5 m2(A6). P6 T8 M2(B1) M4+m1(B2). P7 T1×2(C1,C2) T2(leave) T3(C3).
- No placeholders: every item names file:line + exact current text or the grep to locate it.
- Type consistency: `statsAppLabel` signature defined once in C3 and used by both the composable and the test.
