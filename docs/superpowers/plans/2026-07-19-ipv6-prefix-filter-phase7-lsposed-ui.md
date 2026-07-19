# IPv6 Prefix Filter — Phase 7: LSPosed Compose UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give users a Compose editor for the global `ipv6PrefixRules` list (iface, prefix, prefixLen; cap 8) in the LSPosed app, with activator-strict validation at entry time, a correct label for the stats sentinel uid `0xFFFFFFFF`, a changelog fragment, and on-device verification on the Nord 3.

**Architecture:** The storage layer already round-trips the rules: `CanonicalConfig.ipv6PrefixRules: List<CanonicalIpv6PrefixRule>` parses/serializes/carries through every existing save path (`StorageConfig.kt:16,27-31,221-239,348,406-408,447-461`), and `CanonicalConfigRepository.persist` writes the canonical JSON + re-runs the native activator in one root transaction (`CanonicalConfigRepository.kt:42-55`). Phase 7 adds three things on top: (1) a pure validation module mirroring the Rust activator's strict rules bit-for-bit (the Kotlin parser is best-effort and the data class has no `init` validation — the UI is the only gate that stops a bad list from hitting disk, where the activator would then reject the WHOLE config); (2) a new settings screen cloned from the `HiddenAppsSettingsScreen` pattern (Scaffold + save bar + dirty tracking + snackbar), wired into Settings like `HiddenAppsSettingsScreen` is; (3) a one-line sentinel special-case in stats so `0xFFFFFFFF` renders "Global (not one app)" instead of "uid 4294967295".

**Tech Stack:** Kotlin 2.4.0, Jetpack Compose (BOM 2026.06.00, material3 1.5.0-alpha22, material-icons-extended), minSdk 29 / targetSdk 36, JUnit4 unit tests, ktlint + detekt (`maxIssues: 0`, no baseline) + CPD + Android lint + `checkKotlinSourceSize`.

---

## Verified facts (recon 2026-07-19 — trust these; verified against HEAD `a3814f8`, branch `feat/ipv6-prefix-filter`)

1. **Data flow (all existing, do not rebuild):** `StorageConfig.kt:27-31` `CanonicalIpv6PrefixRule(iface, prefix, prefixLen)` — plain data class, NO validation. `parseIpv6PrefixRules` (:221-239) is best-effort: checks only `iface.isNotBlank() && iface.length < 16`, `prefix.isNotBlank()`, `prefixLen in 0..128`; skips malformed entries; does NOT check printable-ASCII, IPv6 parseability, or max 8. `buildCanonicalConfig` carries `ipv6PrefixRules = existing?.ipv6PrefixRules ?: emptyList()` (:348) — every existing save path preserves the list. `canonicalConfigJson` emits the key only when non-empty (:406-408).
2. **Persist path:** `CanonicalConfigRepository.persist(config, coupledCommands, activation, timeoutSec)` (`CanonicalConfigRepository.kt:42-55`) = one root `su` transaction: atomic JSON write, then `ConfigChannels.nativeActivatorCommand()` (default `CanonicalActivation(native = true)`) → kmod > KPM > Zygisk activator re-run. **No separate re-activation trigger exists or is needed.** On success it invalidates `RootSnapshotCache`/`TargetsCache`/`DashboardCache`/`StatisticsCache`. Save pattern to copy: `writeHiddenApps` (`HiddenAppsSettingsScreen.kt:479-496`) → `persist(canonical).exitCode`, then `TargetsCache.refreshAfterSave(scope, context)`.
3. **Read path for the screen:** `TargetsCache.snapshot` → `TargetsSnapshot.canonicalConfig` → `buildCanonicalConfigFromTargetsSnapshot(snapshot)` (`StorageConfig.kt:352`); `TargetsCache.ensureLoaded(scope, context)` in `LaunchedEffect(Unit)` (pattern: `HiddenAppsSettingsScreen.kt:72,84-87,95`).
4. **Rust strict validator to mirror exactly** (`crates/activator/src/model.rs:306-337`, `validate_ipv6_prefix_rules`): iface — `is_empty() || len() > 15 || !bytes().all(|b| (0x21..=0x7e).contains(&b))` → error "ipv6PrefixRules.iface must be 1..15 printable ASCII chars, no spaces"; prefix — `parse::<std::net::Ipv6Addr>().is_err()` → "ipv6PrefixRules.prefix must be a valid IPv6 address"; prefixLen — `> 128` → "ipv6PrefixRules.prefixLen must be within 0..=128". Max 8 enforced at the wire layer (`MAX_PREFIX_RULES = 8`, `crates/protocol`); activator warns+truncates over 8. Rust `Ipv6Addr::from_str` accepts: 8×(1-4 hex), one `::` compression (0-7 explicit groups with it, exactly 8 without), embedded dotted-quad IPv4 as the LAST group only (counts as 2 groups; octets 0-255, no leading zeros); rejects zone ids (`%eth0`), brackets, bare IPv4, empty groups, >1 `::`.
5. **No IPv6 literal parser exists in the app or its deps.** `InetAddress.getByName` does DNS for non-numeric input (main-thread/network hazard) — MUST NOT be used. Plan ships a small pure-Kotlin literal parser + tests.
6. **Navigation = boolean state-hoisting, no NavHost.** Copy the exact pattern from `SettingsScreen.kt:101-114` (`var hiddenAppsOpen by remember { mutableStateOf(false) }` + `if (hiddenAppsOpen) { HiddenAppsSettingsScreen(onBack = { hiddenAppsOpen = false }); return }`). Section-row pattern: `DiagnosticsSettingsSection` (`SettingsScreen.kt:410-421`) — `SettingsSectionHeader` + `PreferenceRow(title, subtitle, icon, onClick)`. Section list call site: `SettingsScreen.kt:236-244`.
7. **Source-size budgets are HARD** (`app/build.gradle.kts:66-87`, runs inside `:app:detekt`): new files ≤ 700 lines; `SettingsScreen.kt` is EXACTLY 1201 = its shrink-only budget; `StatisticsScreen.kt` is EXACTLY 1102 = its budget. Both files must not grow by even one line. Offset recipes are given per task below.
8. **Stats sentinel:** wire `0xffffffff` parses to `Long` 4294967295 (`Protocol.parseStats`, `Protocol.kt:252-267`). uid→label: `appLabel` (`StatisticsScreen.kt:982-987`) falls back to `stringResource(R.string.statistics_unknown_uid, app.uid)` = "uid %1$d" when `packageNames` is empty — sentinel currently renders "uid 4294967295". `docs/protocol.md:285-289`: sentinel = "global, not attributable to one app" (global prefix-filter hits). `AppProbeStats.uid` is `Long` (`ProbeStats.kt:89-101`). `ProbeStats.kt` is 217 lines, NOT budget-capped.
9. **Quality gates (all run in fork CI via stock `ci.yml` on push to any `main`... NOTE: ci.yml triggers on `push: branches: [main]` and `pull_request`; this fork branch is `feat/ipv6-prefix-filter` — previous phases pushed this branch and got fork CI via the `prefix-*.yml` workflows + PR-less branch push; the lsposed gates live in the rust/lsposed job `ktlint "lsposed/app/src/**/*.kt"` + `cd lsposed && ./gradlew :app:detekt cpdCheck :app:lintDebug :app:testDebugUnitTest` (`ci.yml:174-184`). Verify which workflow actually fired on the first push of Task 0 (`gh run list --branch feat/ipv6-prefix-filter --limit 5`); if stock ci.yml does not fire on this branch, run the two gate commands LOCALLY before every push — they are the hard gate either way.**
10. **detekt tripwires** (`lsposed/config/detekt/detekt.yml`, all `ignoreAnnotated: ['Composable']`): LongMethod 60, CyclomaticComplex/CognitiveComplex 20, LongParameterList 8 (functions), NestedBlockDepth 5, LargeClass 600. `UnusedPrivateMember`/`UnusedPrivateProperty` ON (dead private helpers FAIL). ktlint: no `max_line_length` in `.editorconfig` → ktlint-official default 140; trailing commas pin multi-line wrapping (do not try to "collapse" existing Compose calls — ktlint re-expands them).
11. **Strings are bilingual, always:** every user-visible string in BOTH `res/values/strings.xml` AND `res/values-ru/strings.xml`, used via `stringResource`. Android lint has `error += "UnusedResources"` (`app/build.gradle.kts:306`) — a string defined but not referenced FAILS the build, so each task ships its strings together with the code that uses them.
12. **Changelog:** `./scripts/changelog.py added "<EN>" "<RU>"` → one `changelog.d/added-<slug>-<hex4>.md` fragment; commit it with the change. REQUIRED here (user-visible feature). No AI mentions, no `#NN` in any commit/fragment.
13. **Components to reuse:** `GroupedCard(index, count)` (`ui/components/Enhanced.kt:80`), `EnhancedButton`/`EnhancedOutlinedButton` (:122,:155), `PreferenceRow` (`ui/components/Preference.kt:38`, index/count default to standalone), `HelpAccordion(prefKey, title) { content }` (`HelpAccordion.kt:52`, usage `HiddenAppsSettingsScreen.kt:268-277`), `AppColors.screenBackground`/`topBarContainer`/`toolbarActionContainer`, `StatusColors.*` (never `colorScheme.errorContainer` for status). material-icons-extended IS a dependency (`app/build.gradle.kts:326`).
14. **Screen pattern to clone** (`HiddenAppsSettingsScreen.kt`, 497 lines — read it first): `TargetsCache`/`AppListCache` collectAsState, `LaunchedEffect(Unit)` ensureLoaded, `LaunchedEffect(snackMessage)` snackbar, `initialX = remember(canonical) {...}` + `var x by remember(initialX)`, `dirty = x != initialX`, loading spinner when snapshot null, `BackHandler`, bottom save bar (`HiddenAppsSaveBar` :435-477: `Surface(tonalElevation = 3.dp)` + summary + `EnhancedButton(enabled = dirty && !saving)` + spinner), save via `scope.launch { withContext(Dispatchers.IO) { ...persist... } }` + `TargetsCache.refreshAfterSave`.
15. **Device state (Nord 3, d78a88ef, Android 16):** canonical JSON on-device = the user's blanket — `{"version":1,"debug":true,"apps":{},"ipv6PrefixRules":[8 × {rmnet_data0-3 × {2409:40e3::/32, 2409:4123::/32}}]}` (669B, root:root 644). kmod + zygisk both project it; shell (uid 2000) sees only link-locals on rmnet_data0-2, system sees the two global /64s. Probe app `dev.vpnhide.nlprobe` (uid 10418) installed = Phase 6/7 harness. Post-reboot interactive-ksu write wall: adb `su` writes to /data/system, /data/adb/modules, /proc/vpnhide_ctl are EACCES this boot (reads intermittent) — verification MUST be read-only over adb; the ONLY write path that works post-reboot is the app's own persist + the boot activator. LSPosed app install state on the device is unknown — Task 5 checks.
16. **Carried finding to watch:** the activator once projected a stale uid (0x28ae) after a probe reinstall churned uids; boot re-resolution self-heals. While exercising the JSON write path in Task 5, compare `grep '^target' targets.txt` uids against `pm list packages -U` output.
17. **Commit/branch discipline:** branch `feat/ipv6-prefix-filter`; push ONLY to `fork` (awesomeblossom898-spec/vpnhide), NEVER `origin` (upstream). Commit style `<scope>: <message>` (e.g. `lsposed: ...`). Repo-local git identity only (vpnhide-prefix / vpnhide-prefix@localhost) — never touch global git config. No `VERSION` bump, no `release.py`.
18. **GUI discipline (repo rule):** do not drive the GUI to read DIAGNOSTICS check results, and never edit prefs via su. Driving/reading the NEW editor screen for feature verification (screencap + visual read) is not diagnostics — allowed, but prefer asking the user to perform the taps first (standing practice).
19. `DiagnosticsSettingsScreen` composable lives in `SettingsScreen.kt:312-353`; the `DiagnosticsSettingsSection` ROW lives at `SettingsScreen.kt:410-421` (12 lines). `DiagnosticsScreen.kt` exists as a separate, non-budgeted file in the same package — moving the row there needs no new imports beyond what it already has (verify; same package = no import of the row itself needed anywhere).
20. `generated/IfaceLists.kt` `isVpnIface(name)` exists (codegen from `data/interfaces.toml`) — optional soft-warning source if a rule's iface looks like a VPN tunnel. NOT in scope (YAGNI); noted for Phase 8 polish.

## Scope boundary

- **In:** `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/Ipv6PrefixRulesData.kt` (new), `PrefixRulesSettingsScreen.kt` (new), `SettingsScreen.kt` (wiring, budget-neutral), `StatisticsScreen.kt` (sentinel, line-neutral), `ProbeStats.kt` (sentinel const), `res/values*/strings.xml` (en+ru), `lsposed/app/src/test/kotlin/dev/okhsunrog/vpnhide/Ipv6PrefixRulesDataTest.kt` (new), one changelog fragment, on-device verification.
- **Out:** activator/protocol/kernel/zygisk changes (none needed — facts 1-2, 4); `parseIpv6PrefixRules` strictness changes (best-effort parse is deliberate — strictness lives at entry/persist time); reorder/dedupe semantics (Rust doesn't reject duplicates — parity); `isVpnIface` soft warning (Phase 8); CI workflow changes (verify-then-decide per fact 9); upstream PR (Phase 8); VERSION/release.
- **Hard constraints:** SettingsScreen.kt ≤ 1201 and StatisticsScreen.kt ≤ 1102 after every commit (`:app:detekt` enforces); new files ≤ 700; every new string used + bilingual; validation verdicts MUST equal the Rust validator's on every input (iface byte-range check makes length units coincide — ASCII-only strings pass both); NO `InetAddress.getByName`; no `#NN`; no AI mentions; push to `fork` only; the device-side verification is read-only over adb (fact 15) except actions performed by the user in the app's own UI.

---

### Task 0: Pure validation module + editable draft model + unit tests

**Files:**
- Create: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/Ipv6PrefixRulesData.kt`
- Test: `lsposed/app/src/test/kotlin/dev/okhsunrog/vpnhide/Ipv6PrefixRulesDataTest.kt`

Context: this is the entry-time gate. The Rust activator rejects a whole config on any invalid rule (fact 4); the UI must never persist such a list. Pure top-level functions in a `*Data.kt` file per `lsposed/AGENTS.md` (pattern: `PortPolicyData.kt`).

- [ ] **Step 1: Write the failing test**

`Ipv6PrefixRulesDataTest.kt` (JUnit4, mirrors the existing test style in `StorageConfigTest.kt`):

```kotlin
package dev.okhsunrog.vpnhide

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Ipv6PrefixRulesDataTest {
    private fun rule(iface: String = "rmnet_data0", prefix: String = "2409:40e3::", prefixLen: String = "32") =
        EditablePrefixRule(iface = iface, prefix = prefix, prefixLen = prefixLen)

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
        assertNull(validateEditablePrefixRules(listOf(rule(iface = "fifteen_char_if"))) )
    }

    @Test
    fun `prefix must be a valid ipv6 literal`() {
        val good = listOf("::", "2409:40e3::", "fe80::1", "::ffff:1.2.3.4", "0:0:0:0:0:ffff:1.2.3.4", "2001:db8:85a3:8d3:1319:8a2e:370:7348", "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", "ABCD::ef01")
        good.forEach { assertTrue("expected valid: $it", isValidIpv6Literal(it)) }
        val bad = listOf("", "1.2.3.4", "gg::1", "1::2::3", "fe80::1%eth0", "12345::", ":1::2", "1::2:", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "0:0:0:0:0:ffff:1.2.3.256", "0:0:0:0:0:ffff:01.2.3.4", "::ffff:1.2.3", "2409:40e3::/32")
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
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd lsposed && ./gradlew :app:testDebugUnitTest --tests "dev.okhsunrog.vpnhide.Ipv6PrefixRulesDataTest"`
Expected: FAIL — unresolved references (`EditablePrefixRule`, `validateEditablePrefixRules`, `isValidIpv6Literal`, …).

- [ ] **Step 3: Implement `Ipv6PrefixRulesData.kt`**

```kotlin
package dev.okhsunrog.vpnhide

// Entry-time validation for the global ipv6PrefixRules editor. Mirrors the
// activator's strict validator bit-for-bit (crates/activator/src/model.rs
// validate_ipv6_prefix_rules) so the UI never persists a list the activator
// would reject wholesale. The canonical-JSON parser stays best-effort by
// design; strictness lives here, at entry/persist time.

internal const val MAX_IPV6_PREFIX_RULES = 8

internal data class EditablePrefixRule(
    val iface: String = "",
    val prefix: String = "",
    val prefixLen: String = "",
)

internal enum class PrefixRuleField { Iface, Prefix, PrefixLen }

internal enum class PrefixRuleIssue(val field: PrefixRuleField?) {
    IfaceInvalid(PrefixRuleField.Iface),
    PrefixInvalid(PrefixRuleField.Prefix),
    PrefixLenInvalid(PrefixRuleField.PrefixLen),
    TooManyRules(null),
}

internal data class PrefixRuleError(
    val ruleIndex: Int,
    val issue: PrefixRuleIssue,
) {
    val field: PrefixRuleField?
        get() = issue.field
}

internal fun CanonicalIpv6PrefixRule.toEditable(): EditablePrefixRule =
    EditablePrefixRule(iface = iface, prefix = prefix, prefixLen = prefixLen.toString())

internal fun EditablePrefixRule.toCanonicalOrNull(): CanonicalIpv6PrefixRule? {
    val plen = prefixLen.trim().toIntOrNull() ?: return null
    return CanonicalIpv6PrefixRule(iface = iface.trim(), prefix = prefix.trim(), prefixLen = plen)
}

// First invalid field of a single draft rule, or null when the rule is clean.
internal fun prefixRuleFieldError(rule: EditablePrefixRule): PrefixRuleField? =
    when {
        !isValidIface(rule.iface.trim()) -> PrefixRuleField.Iface
        !isValidIpv6Literal(rule.prefix.trim()) -> PrefixRuleField.Prefix
        rule.prefixLen.trim().toIntOrNull() !in 0..128 -> PrefixRuleField.PrefixLen
        else -> null
    }

// First error across the draft list (cap violation wins), or null when the
// whole list may be persisted.
internal fun validateEditablePrefixRules(rules: List<EditablePrefixRule>): PrefixRuleError? {
    if (rules.size > MAX_IPV6_PREFIX_RULES) return PrefixRuleError(-1, PrefixRuleIssue.TooManyRules)
    rules.forEachIndexed { index, rule ->
        when (prefixRuleFieldError(rule)) {
            PrefixRuleField.Iface -> return PrefixRuleError(index, PrefixRuleIssue.IfaceInvalid)
            PrefixRuleField.Prefix -> return PrefixRuleError(index, PrefixRuleIssue.PrefixInvalid)
            PrefixRuleField.PrefixLen -> return PrefixRuleError(index, PrefixRuleIssue.PrefixLenInvalid)
            null -> Unit
        }
    }
    return null
}

private fun isValidIface(iface: String): Boolean =
    iface.isNotEmpty() && iface.length <= 15 && iface.all { it.code in 0x21..0x7e }

// Strict IPv6 literal check mirroring Rust std::net::Ipv6Addr::from_str: one
// optional "::" compression, 1-4 hex digits per group, embedded dotted-quad
// IPv4 as the last group only (counts as two groups; octets 0-255 without
// leading zeros). No DNS, no zone ids, no brackets. Do NOT replace with
// InetAddress.getByName — it resolves non-numeric input over the network.
internal fun isValidIpv6Literal(value: String): Boolean {
    if (value.isEmpty()) return false
    val compression = value.indexOf("::")
    if (compression >= 0 && value.indexOf("::", compression + 2) >= 0) return false
    val head = if (compression >= 0) value.substring(0, compression) else value
    val tail = if (compression >= 0) value.substring(compression + 2) else ""
    val groups = (splitGroups(head) ?: return false) + (splitGroups(tail) ?: return false)
    var count = 0
    groups.forEachIndexed { index, group ->
        if (group.length in 1..4 && group.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
            count += 1
        } else {
            if (index != groups.lastIndex || !isValidIpv4Quad(group)) return false
            count += 2
        }
    }
    return if (compression >= 0) count < 8 else count == 8
}

private fun splitGroups(part: String): List<String>? {
    if (part.isEmpty()) return emptyList()
    val groups = part.split(":")
    if (groups.any { it.isEmpty() }) return null
    return groups
}

private fun isValidIpv4Quad(value: String): Boolean {
    val parts = value.split(".")
    if (parts.size != 4) return false
    return parts.all { part ->
        part.length in 1..3 &&
            part.all { it in '0'..'9' } &&
            !(part.length > 1 && part.startsWith("0")) &&
            part.toInt() <= 255
    }
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd lsposed && ./gradlew :app:testDebugUnitTest --tests "dev.okhsunrog.vpnhide.Ipv6PrefixRulesDataTest"`
Expected: PASS, all 7 tests. Then the full module unit suite: `cd lsposed && ./gradlew :app:testDebugUnitTest` — PASS, no regressions.

- [ ] **Step 5: Local gates**

Run: `ktlint "lsposed/app/src/**/*.kt"` (0 violations) and `cd lsposed && ./gradlew :app:detekt cpdCheck` (0 issues; new file ≤ 700 lines is enforced by checkKotlinSourceSize inside detekt).
Expected: all clean. Fix formatting with `ktlint --format` only on the NEW files if needed.

- [ ] **Step 6: Commit + push + CI**

```bash
git add lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/Ipv6PrefixRulesData.kt lsposed/app/src/test/kotlin/dev/okhsunrog/vpnhide/Ipv6PrefixRulesDataTest.kt
git commit -m "lsposed: entry-time ipv6PrefixRules validation mirroring the activator"
git push fork feat/ipv6-prefix-filter
gh run list --branch feat/ipv6-prefix-filter --limit 5
```
Expected: CI workflow(s) that fired go green (fact 9 — if no lsposed gate fires on this branch, the local gates from Step 5 are the record; note which fired in the task report).

---

### Task 1: The prefix-rules editor screen + bilingual strings

**Files:**
- Create: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/PrefixRulesSettingsScreen.kt` (≤ 700 lines)
- Modify: `lsposed/app/src/main/res/values/strings.xml` (insert after the `settings_hidden_apps*` cluster, ~line 488)
- Modify: `lsposed/app/src/main/res/values-ru/strings.xml` (same relative spot, near `settings_hidden_apps` at line 434)

Context: clone of `HiddenAppsSettingsScreen.kt` (fact 14) reduced to a form editor — first add/remove-row editor in the app. The 14 new strings in this task are all referenced by the screen itself (fact 11), so this task is lint-self-contained; the one settings-row subtitle string (`settings_prefix_rules_sub`) ships in Task 2 with the row that uses it. The screen is `internal` and not yet wired (Task 2) — Kotlin/AGP does not fail on an unused internal composable and detekt's UnusedPrivateMember only covers `private` symbols, so the intermediate commit is gate-clean.

- [ ] **Step 1: Add the strings (en)**

Insert into `res/values/strings.xml` after `<string name="settings_auto_hide_failed">…</string>`:

```xml
    <string name="settings_prefix_rules">IPv6 prefix rules</string>
    <string name="prefix_rules_help_body">Each rule hides global IPv6 addresses that fall within PREFIX/LEN on the named interface (kernel interface name, e.g. rmnet_data0) from apps. Up to 8 rules; rules apply to every app, targeted or not. The adb shell view (uid 2000) reflects only the kernel backends (.ko/KPM); the Zygisk backend filters inside hooked app processes instead.</string>
    <string name="prefix_rule_iface">Interface</string>
    <string name="prefix_rule_prefix">Prefix (IPv6)</string>
    <string name="prefix_rule_prefix_len">Prefix length</string>
    <string name="prefix_rule_add">Add rule</string>
    <string name="prefix_rule_remove">Remove rule</string>
    <string name="prefix_rules_empty">No prefix rules — every IPv6 address is visible.</string>
    <string name="prefix_rules_saved">Prefix rules saved.</string>
    <string name="prefix_rules_failed">Failed to save prefix rules.</string>
    <string name="prefix_rule_error_iface">1–15 printable ASCII chars, no spaces</string>
    <string name="prefix_rule_error_prefix">Enter a valid IPv6 address</string>
    <string name="prefix_rule_error_prefix_len">0–128</string>
    <string name="prefix_rules_count">%1$d of %2$d rules</string>
```

- [ ] **Step 2: Add the strings (ru)**

Insert into `res/values-ru/strings.xml` near the `settings_hidden_apps` entry:

```xml
    <string name="settings_prefix_rules">Правила префиксов IPv6</string>
    <string name="prefix_rules_help_body">Каждое правило скрывает глобальные адреса IPv6, попадающие в ПРЕФИКС/ДЛИНУ на указанном интерфейсе (имя интерфейса ядра, например rmnet_data0), от приложений. До 8 правил; правила действуют на все приложения, целевые или нет. Представление adb shell (uid 2000) отражает только ядерные бэкенды (.ko/KPM); бэкенд Zygisk фильтрует внутри процессов перехваченных приложений.</string>
    <string name="prefix_rule_iface">Интерфейс</string>
    <string name="prefix_rule_prefix">Префикс (IPv6)</string>
    <string name="prefix_rule_prefix_len">Длина префикса</string>
    <string name="prefix_rule_add">Добавить правило</string>
    <string name="prefix_rule_remove">Удалить правило</string>
    <string name="prefix_rules_empty">Нет правил — все адреса IPv6 видны.</string>
    <string name="prefix_rules_saved">Правила префиксов сохранены.</string>
    <string name="prefix_rules_failed">Не удалось сохранить правила префиксов.</string>
    <string name="prefix_rule_error_iface">1–15 печатаемых ASCII-символов, без пробелов</string>
    <string name="prefix_rule_error_prefix">Введите корректный адрес IPv6</string>
    <string name="prefix_rule_error_prefix_len">0–128</string>
    <string name="prefix_rules_count">Правил: %1$d из %2$d</string>
```

- [ ] **Step 3: Write `PrefixRulesSettingsScreen.kt`**

Complete file (pattern per fact 14; components per fact 13; validation from Task 0):

```kotlin
package dev.okhsunrog.vpnhide

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.okhsunrog.vpnhide.ui.components.EnhancedButton
import dev.okhsunrog.vpnhide.ui.components.EnhancedOutlinedButton
import dev.okhsunrog.vpnhide.ui.components.GroupedCard
import dev.okhsunrog.vpnhide.ui.theme.AppColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PrefixRulesSettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val targets by TargetsCache.snapshot.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }
    var saving by remember { mutableStateOf(false) }
    var attemptedSave by remember { mutableStateOf(false) }
    var snackMessage by remember { mutableStateOf<String?>(null) }
    val savedMessage = stringResource(R.string.prefix_rules_saved)
    val failedMessage = stringResource(R.string.prefix_rules_failed)

    LaunchedEffect(Unit) { TargetsCache.ensureLoaded(scope, context) }
    LaunchedEffect(snackMessage) {
        snackMessage?.let {
            snackbarHostState.showSnackbar(it, duration = SnackbarDuration.Short)
            snackMessage = null
        }
    }

    val canonical = targets?.let(::buildCanonicalConfigFromTargetsSnapshot)
    val initialRules =
        remember(canonical) {
            canonical?.ipv6PrefixRules?.map(CanonicalIpv6PrefixRule::toEditable).orEmpty()
        }
    var rules by remember(initialRules) { mutableStateOf(initialRules) }
    val dirty = rules != initialRules

    BackHandler(onBack = onBack)

    Scaffold(
        containerColor = AppColors.screenBackground,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_prefix_rules)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
                colors =
                    TopAppBarDefaults.topAppBarColors(
                        containerColor = AppColors.topBarContainer,
                        titleContentColor = MaterialTheme.colorScheme.onSurface,
                        navigationIconContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    ),
            )
        },
        bottomBar = {
            PrefixRulesSaveBar(
                ruleCount = rules.size,
                enabled = dirty && !saving,
                saving = saving,
                onSave = {
                    attemptedSave = true
                    val base = canonical ?: return@PrefixRulesSaveBar
                    if (validateEditablePrefixRules(rules) != null) return@PrefixRulesSaveBar
                    val draft = rules.mapNotNull(EditablePrefixRule::toCanonicalOrNull)
                    saving = true
                    scope.launch {
                        val exit =
                            withContext(Dispatchers.IO) {
                                CanonicalConfigRepository.persist(base.copy(ipv6PrefixRules = draft)).exitCode
                            }
                        saving = false
                        attemptedSave = false
                        snackMessage = if (exit == 0) savedMessage else failedMessage
                        if (exit == 0) {
                            TargetsCache.refreshAfterSave(scope, context)
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        if (canonical == null) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
            return@Scaffold
        }

        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            HelpAccordion(
                prefKey = "prefix_rules",
                title = stringResource(R.string.settings_prefix_rules),
            ) {
                Text(
                    text = stringResource(R.string.prefix_rules_help_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (rules.isEmpty()) {
                Text(
                    text = stringResource(R.string.prefix_rules_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    itemsIndexed(rules) { index, rule ->
                        PrefixRuleCard(
                            index = index,
                            count = rules.size,
                            rule = rule,
                            attemptedSave = attemptedSave,
                            onChange = { updated ->
                                rules = rules.toMutableList().apply { set(index, updated) }
                            },
                            onRemove = {
                                rules = rules.toMutableList().apply { removeAt(index) }
                            },
                        )
                    }
                }
            }
            EnhancedOutlinedButton(
                onClick = { rules = rules + EditablePrefixRule() },
                enabled = rules.size < MAX_IPV6_PREFIX_RULES,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.Add, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.prefix_rule_add))
            }
        }
    }
}

@Composable
private fun PrefixRuleCard(
    index: Int,
    count: Int,
    rule: EditablePrefixRule,
    attemptedSave: Boolean,
    onChange: (EditablePrefixRule) -> Unit,
    onRemove: () -> Unit,
) {
    val fieldError = prefixRuleFieldError(rule)
    GroupedCard(index = index, count = count) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 16.dp, top = 8.dp, end = 4.dp, bottom = 8.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                PrefixRuleTextField(
                    value = rule.iface,
                    label = stringResource(R.string.prefix_rule_iface),
                    error = fieldError == PrefixRuleField.Iface && (attemptedSave || rule.iface.isNotEmpty()),
                    errorText = stringResource(R.string.prefix_rule_error_iface),
                    onValueChange = { onChange(rule.copy(iface = it)) },
                )
                PrefixRuleTextField(
                    value = rule.prefix,
                    label = stringResource(R.string.prefix_rule_prefix),
                    error = fieldError == PrefixRuleField.Prefix && (attemptedSave || rule.prefix.isNotEmpty()),
                    errorText = stringResource(R.string.prefix_rule_error_prefix),
                    onValueChange = { onChange(rule.copy(prefix = it)) },
                )
                PrefixRuleTextField(
                    value = rule.prefixLen,
                    label = stringResource(R.string.prefix_rule_prefix_len),
                    error = fieldError == PrefixRuleField.PrefixLen && (attemptedSave || rule.prefixLen.isNotEmpty()),
                    errorText = stringResource(R.string.prefix_rule_error_prefix_len),
                    keyboardType = KeyboardType.Number,
                    onValueChange = { onChange(rule.copy(prefixLen = it)) },
                )
            }
            IconButton(onClick = onRemove) {
                Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.prefix_rule_remove))
            }
        }
    }
}

@Composable
private fun PrefixRuleTextField(
    value: String,
    label: String,
    error: Boolean,
    errorText: String,
    onValueChange: (String) -> Unit,
    keyboardType: KeyboardType = KeyboardType.Text,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        isError = error,
        supportingText = { if (error) Text(errorText) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun PrefixRulesSaveBar(
    ruleCount: Int,
    enabled: Boolean,
    saving: Boolean,
    onSave: () -> Unit,
) {
    Surface(tonalElevation = 3.dp) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = stringResource(R.string.prefix_rules_count, ruleCount, MAX_IPV6_PREFIX_RULES),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            EnhancedButton(onClick = onSave, enabled = enabled) {
                if (saving) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(8.dp))
                }
                Text(stringResource(R.string.btn_save))
            }
        }
    }
}
```

Notes for the implementer: `R.string.action_back`, `R.string.btn_save`, `HelpAccordion`, `TargetsCache.refreshAfterSave`, `buildCanonicalConfigFromTargetsSnapshot`, `CanonicalConfigRepository.persist` all already exist (facts 2-3, 13-14). If ktlint reflows anything, accept its output on this new file only.

- [ ] **Step 4: Build + unit tests + gates**

Run: `cd lsposed && ./gradlew :app:assembleDebug :app:testDebugUnitTest :app:detekt cpdCheck :app:lintDebug` and `ktlint "lsposed/app/src/**/*.kt"`.
Expected: BUILD SUCCESSFUL everywhere; `checkKotlinSourceSize` passes (new file ≤ 700); lint UnusedResources passes (all 14 strings referenced by the screen); no detekt findings (`PrefixRuleCard` has 6 params < 8; helpers are used).

- [ ] **Step 5: Commit + push**

```bash
git add lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/PrefixRulesSettingsScreen.kt lsposed/app/src/main/res/values/strings.xml lsposed/app/src/main/res/values-ru/strings.xml
git commit -m "lsposed: ipv6PrefixRules editor screen with entry-time validation"
git push fork feat/ipv6-prefix-filter
```

---

### Task 2: Wire the screen into Settings (budget-neutral) + changelog fragment

**Files:**
- Modify: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/SettingsScreen.kt` (MUST stay ≤ 1201 lines — fact 7)
- Modify: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/DiagnosticsScreen.kt` (receives the moved section row; not budget-capped)
- Create: `changelog.d/added-<slug>-<hex4>.md` (via script)

Context: SettingsScreen.kt is exactly at its 1201 shrink-only budget (fact 7). The wiring needs +6 lines; the offset is moving the existing `DiagnosticsSettingsSection` row composable (12 lines) into `DiagnosticsScreen.kt` (same package — call sites unchanged, cohesion improved: diagnostics row lives with the diagnostics screen). Net: 1201 − 12 − (unused-import cleanup, if any) + 6 ≤ 1195.

- [ ] **Step 1: Create the changelog fragment FIRST (repo rule: fragment before user-visible commit)**

```bash
./scripts/changelog.py added "IPv6 prefix rules editor in Settings: configure up to 8 global iface/prefix/length rules with entry-time validation; global prefix-filter hits now show as \"Global (not one app)\" in Statistics" "Редактор правил префиксов IPv6 в настройках: до 8 глобальных правил интерфейс/префикс/длина с проверкой при вводе; глобальные попадания фильтра префиксов теперь отображаются как \"Глобально (не одно приложение)\" в статистике"
```
Expected: one new `changelog.d/added-*.md`. (Quote the inner quotes exactly as above or simplify wording to avoid nesting; the file content is what matters.)

- [ ] **Step 2: Move `DiagnosticsSettingsSection` out of SettingsScreen.kt**

Cut the whole composable (`SettingsScreen.kt:410-421`, `@Composable private fun DiagnosticsSettingsSection(onOpen: () -> Unit) { ... }`) and append it to `DiagnosticsScreen.kt`, changing `private` to `internal` (cross-file visibility, same module). Add any missing imports to `DiagnosticsScreen.kt` (`androidx.compose.foundation.layout.Arrangement`, `Column`, `androidx.compose.material.icons.filled.CheckCircle`, `androidx.compose.ui.res.stringResource`, `PreferenceRow` — check what it already has; `SettingsSectionHeader` is same-package). In `SettingsScreen.kt`, remove now-unused imports ONLY if ktlint reports them (`no-unused-imports` fails the build) — `Icons.Default.CheckCircle` is the likely one; verify no other usage remains in SettingsScreen.kt before removing (`grep -n "CheckCircle" SettingsScreen.kt`).

- [ ] **Step 3: Add the wiring (exactly +6 lines in SettingsScreen.kt)**

After `var hiddenAppsOpen by remember { mutableStateOf(false) }` (line 102), add:

```kotlin
    var prefixRulesOpen by remember { mutableStateOf(false) }
```

After the `if (hiddenAppsOpen) { ... return }` block (line 114), add:

```kotlin
    if (prefixRulesOpen) {
        PrefixRulesSettingsScreen { prefixRulesOpen = false }
        return
    }
```

In the section list (`SettingsScreen.kt:236-244`), after `DiagnosticsSettingsSection(onOpen = { diagnosticsOpen = true })`, add:

```kotlin
            PrefixRulesSettingsSection(onOpen = { prefixRulesOpen = true })
```

- [ ] **Step 4: Add the settings-row subtitle string (both locales)**

en (`values/strings.xml`, next to `settings_prefix_rules`):

```xml
    <string name="settings_prefix_rules_sub">Hide configured IPv6 prefixes on matching interfaces</string>
```

ru (`values-ru/strings.xml`):

```xml
    <string name="settings_prefix_rules_sub">Скрывать заданные префиксы IPv6 на указанных интерфейсах</string>
```

- [ ] **Step 5: Add the section-row composable to `PrefixRulesSettingsScreen.kt`**

Append (keeps the entry point next to its screen; `Icons.Default.Public` ships in material-icons-extended, fact 13):

```kotlin
@Composable
internal fun PrefixRulesSettingsSection(onOpen: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        SettingsSectionHeader(stringResource(R.string.settings_prefix_rules))
        PreferenceRow(
            title = stringResource(R.string.settings_prefix_rules),
            subtitle = stringResource(R.string.settings_prefix_rules_sub),
            icon = Icons.Default.Public,
            onClick = onOpen,
        )
    }
}
```

Add the missing imports to `PrefixRulesSettingsScreen.kt`: `androidx.compose.material.icons.filled.Public`, `dev.okhsunrog.vpnhide.ui.components.PreferenceRow` (and confirm `Column`/`Arrangement`/`stringResource` are already imported — they are, per the Task 1 file). `SettingsSectionHeader` is same-package.

- [ ] **Step 6: Verify budgets + gates**

Run: `wc -l lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/SettingsScreen.kt` → MUST be ≤ 1201. Then `ktlint "lsposed/app/src/**/*.kt"` and `cd lsposed && ./gradlew :app:assembleDebug :app:detekt cpdCheck :app:lintDebug :app:testDebugUnitTest`.
Expected: all green. If SettingsScreen.kt somehow exceeds 1201, find additional ktlint-clean shrinkage (unused imports, dead code) — do NOT raise the budget in build.gradle.kts (that defeats the ratchet; treat as a bug in this task).

- [ ] **Step 7: Commit + push**

```bash
git add lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/SettingsScreen.kt lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/DiagnosticsScreen.kt lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/PrefixRulesSettingsScreen.kt lsposed/app/src/main/res/values/strings.xml lsposed/app/src/main/res/values-ru/strings.xml changelog.d/
git commit -m "lsposed: settings entry for the prefix rules editor"
git push fork feat/ipv6-prefix-filter
gh run list --branch feat/ipv6-prefix-filter --limit 3
```
Expected: CI green.

---

### Task 3: Stats sentinel uid renders "Global (not one app)"

**Files:**
- Modify: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/ProbeStats.kt` (add const; 217 → ~220 lines, not budget-capped)
- Modify: `lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/StatisticsScreen.kt` (MUST stay ≤ 1102 — the edit below nets −2 lines)
- Modify: `lsposed/app/src/main/res/values/strings.xml` + `res/values-ru/strings.xml` (one string each, near `statistics_unknown_uid`)

Context: fact 8. The sentinel uid `0xFFFFFFFF` (4294967295L) marks global prefix-filter hits — "global, not attributable to one app" (`docs/protocol.md:285-289`).

- [ ] **Step 1: Add the string (both locales)**

en (`values/strings.xml`, after `statistics_unknown_uid`):

```xml
    <string name="statistics_global_uid">Global (not one app)</string>
```

ru (`values-ru/strings.xml`, after `statistics_unknown_uid`):

```xml
    <string name="statistics_global_uid">Глобально (не одно приложение)</string>
```

- [ ] **Step 2: Add the sentinel const to ProbeStats.kt**

Top-level, near the other declarations:

```kotlin
// Sentinel uid attributing global prefix-filter hits (docs/protocol.md §6):
// never a real app uid — render it as "global", not a numeric fallback.
internal const val SENTINEL_UID = 0xFFFFFFFFL
```

- [ ] **Step 3: Rewrite `appLabel` in StatisticsScreen.kt (line-shrinking edit)**

Replace (`StatisticsScreen.kt:982-987`, currently 6 lines):

```kotlin
@Composable
private fun appLabel(app: AppProbeStats): String =
    app.packageNames
        .takeIf { it.isNotEmpty() }
        ?.joinToString(", ")
        ?: stringResource(R.string.statistics_unknown_uid, app.uid)
```

with (4 lines — nets −2, keeping the file ≤ 1100):

```kotlin
@Composable
private fun appLabel(app: AppProbeStats): String =
    if (app.uid == SENTINEL_UID) stringResource(R.string.statistics_global_uid)
    else app.packageNames.takeIf { it.isNotEmpty() }?.joinToString(", ") ?: stringResource(R.string.statistics_unknown_uid, app.uid)
```

(The `else` line is 139 chars — under the 140 ktlint limit, fact 10. If ktlint disagrees on your version, use the braced if/else form and recover the lines elsewhere in the file with a ktlint-clean collapse; verify `wc -l` ≤ 1102 either way.)

- [ ] **Step 4: Gates**

Run: `wc -l lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/StatisticsScreen.kt` (≤ 1102), `ktlint "lsposed/app/src/**/*.kt"`, `cd lsposed && ./gradlew :app:detekt :app:lintDebug :app:testDebugUnitTest`.
Expected: all green; `statistics_global_uid` referenced (lint UnusedResources passes).

- [ ] **Step 5: Commit + push**

```bash
git add lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/ProbeStats.kt lsposed/app/src/main/kotlin/dev/okhsunrog/vpnhide/StatisticsScreen.kt lsposed/app/src/main/res/values/strings.xml lsposed/app/src/main/res/values-ru/strings.xml
git commit -m "lsposed: render the global prefix-filter stats uid as Global, not a number"
git push fork feat/ipv6-prefix-filter
```

---

### Task 4: Phase-final full gate sweep

**Files:** none (verification only).

- [ ] **Step 1: Full local gate suite, exactly what CI runs**

```bash
ktlint "lsposed/app/src/**/*.kt"
cd lsposed && ./gradlew :app:detekt cpdCheck :app:lintDebug :app:testDebugUnitTest
```
Expected: all green on the first run (each task gated already; this is the belt-and-braces re-check).

- [ ] **Step 2: Release build**

```bash
cd lsposed && ./gradlew :app:assembleRelease
```
Expected: BUILD SUCCESSFUL; APK at `lsposed/app/build/outputs/apk/release/`. If signing fails for a missing keystore, note it — Task 5 falls back to the debug APK.

- [ ] **Step 3: CI verification**

```bash
git push fork feat/ipv6-prefix-filter
gh run list --branch feat/ipv6-prefix-filter --limit 5
```
Expected: every fired workflow green. Record run IDs in the phase ledger.

---

### Task 5: On-device verification (Nord 3, d78a88ef)

**Files:** evidence captured to `C:\Users\akash\Desktop\PRIVACY\p7-lsposed-artifact\` (new dir; pin `cd C:\Users\akash\Desktop\PRIVACY` at the start of every adb command — cwd drifts).

Context: facts 15-16, 18. The device's canonical JSON holds the user's live blanket (8 rules) — the editor will load and display exactly those. adb `su` writes are EACCES this boot; ALL verification over adb is read-only. The user performs the UI taps (standing practice); the harness verifies the on-disk results.

- [ ] **Step 1: Install the app**

```bash
adb -s d78a88ef shell pm list packages | grep -i vpnhide
adb -s d78a88ef install -r lsposed/app/build/outputs/apk/release/app-release.apk   # or the debug APK if release signing was unavailable
adb -s d78a88ef shell am force-stop dev.okhsunrog.vpnhide
adb -s d78a88ef logcat -c
adb -s d78a88ef shell monkey -p dev.okhsunrog.vpnhide -c android.intent.category.LAUNCHER 1
adb -s d78a88ef logcat -d | grep -iE "FATAL|AndroidRuntime" 
```
Expected: package installs, launches, NO FATAL entries. (If the LSPosed app was already installed with a different signature, uninstall first and note the prefs reset; the canonical JSON in /data/system survives — it's not app-private.)

- [ ] **Step 2: User-driven editor flow**

Ask the user to: open the app → Settings (gear) → **IPv6 prefix rules** → confirm the screen lists the 8 blanket rules (rmnet_data0-3 × 2409:40e3::/32 + 2409:4123::/32) → tap **Add rule**, type an iface with a space (`bad iface`) → tap **Save** → confirm the inline error appears on the iface field and NOTHING persists (the save bar validates on submit — quality-review change; the screen's snackbar must NOT show "saved") → remove the bad rule → then reorder without changing the rule SET: delete the FIRST rule (rmnet_data0 / 2409:40e3:: / 32), tap Add rule, re-enter iface `rmnet_data0`, prefix `2409:40e3::`, len `32` (it lands at the END, so the list differs from the initial one and Save enables) → Save → confirm the "saved" snackbar.

Then capture evidence (read-only):

```bash
adb -s d78a88ef shell "su -c 'cat /data/system/vpnhide_config.json'" | tee p7-lsposed-artifact/t5-json-after-save.txt
adb -s d78a88ef shell "su -c 'cat /data/adb/modules/vpnhide_zygisk/targets.txt'" | tee p7-lsposed-artifact/t5-targets-after-save.txt
```
Expected: JSON shows the SAME 8 rules with rmnet_data0/2409:40e3:: now LAST (proves UI → canonical JSON write); targets.txt prefix lines reordered identically (proves the persist triggered the native activator re-run — fact 2). Rule SET is unchanged (sort before diffing): the blanket's semantics are preserved. If either `su` read is denied (intermittent, fact 15), retry a few times; if persistently denied, fall back to `adb -s d78a88ef shell "run-as dev.okhsunrog.vpnhide cat files/..."` being absent → document the denial and rely on Step 3's functional differential.

- [ ] **Step 3: Functional differential still holds (blanket unchanged semantically)**

```bash
adb -s d78a88ef shell "cat /proc/net/if_inet6 | grep -i 2409" ; echo "shell_visible=$?"
adb -s d78a88ef shell "dumpsys connectivity | grep -oE '2409:[0-9a-f:]+' | head -4"
```
Expected: shell sees NO 2409 globals (grep exit 1 = still hidden from uid 2000); system (dumpsys) still sees the two bearer /64s. The blanket survived the UI round-trip functionally.

- [ ] **Step 4: Sentinel label + stale-uid watch**

Generate global-filter hits as shell, then ask the user to open the **Statistics** tab and confirm any "Global (not one app)" row instead of "uid 4294967295" (screenshot fallback: `adb -s d78a88ef shell screencap -p /sdcard/p7stats.png && adb -s d78a88ef pull /sdcard/p7stats.png p7-lsposed-artifact/` then read the PNG visually):

```bash
adb -s d78a88ef shell "cat /proc/net/if_inet6 >/dev/null; cat /proc/net/ipv6_route >/dev/null"
adb -s d78a88ef shell "su -c 'cat /proc/vpnhide_stats'" | tee p7-lsposed-artifact/t5-stats.txt   # retry on intermittent denial
```
Expected: stats contain a `ffffffff` uid row with non-zero counters after the shell reads; the Statistics tab labels it "Global (not one app)". If the kmod stats read is denied this boot, the on-device portion of THIS check is environment-limited — record it; the label logic itself is one comparison reviewed in Task 3.

Stale-uid watch (fact 16):

```bash
adb -s d78a88ef shell "su -c 'grep ^target /data/adb/modules/vpnhide_zygisk/targets.txt'"
adb -s d78a88ef shell "pm list packages -U | grep -E 'nlprobe|vpnhide'"
```
Expected: with the blanket's `apps: {}` there are no target lines — record that; if any target lines appear, their uids MUST match current `pm` uids (no stale projection).

- [ ] **Step 5: Negative-path spot check (activator belt-and-braces, read-only observation)**

This step does NOT write anything from adb. It confirms what happens if an invalid list ever reached the activator — by code inspection plus existing unit coverage only: re-run `cd lsposed && ./gradlew :app:testDebugUnitTest` (green) and cite `validateEditablePrefixRules` gating the Save button (`PrefixRulesSettingsScreen.kt`). No device action.

- [ ] **Step 6: Ledger + handoff update**

Append a `## PHASE 7` section to `C:\Users\akash\Desktop\PRIVACY\vpnhide\.superpowers\sdd\progress.md` (write the section to a separate file first, then `cat file >> progress.md` — heredocs with apostrophes break the Bash tool): tasks T0-T5 results, CI run IDs, device evidence filenames, deviations (e.g. reordered-but-equivalent blanket left on device), the stale-uid observation, and the line "PHASE 7 COMPLETE — LSPosed UI for ipv6PrefixRules + sentinel label, verified on-device at HEAD <sha>. Remaining: Phase 8 (upstream PR)." Refresh the Phase 8 section of `C:\Users\akash\Desktop\PRIVACY\VPNHIDE_PREFIX_SESSION_HANDOFF.md` (fork HEAD sha, CI runs, any new gotchas).

---

## Self-review notes (plan author)

- **Spec coverage:** entry-time validation with activator parity → T0 (+ enforced in T1's screen); cap 8 → T0 + Add-button gate; persist via existing Phase-3 carry-through → T1 (`base.copy(ipv6PrefixRules = …)` + `CanonicalConfigRepository.persist`); sentinel renders a global label → T3; diagnostics wording (shell differentials witness kernel backends only) → T1 help-body string (scoped per fact 15/handoff rule); changelog fragment → T2 Step 1 (before the user-visible commit); stale-uid watch → T5 Step 4; on-device verification → T5.
- **No placeholders:** every code step contains complete code; every command has an expected result.
- **Type consistency:** `EditablePrefixRule`/`PrefixRuleField`/`PrefixRuleIssue`/`PrefixRuleError`/`validateEditablePrefixRules`/`prefixRuleFieldError`/`isValidIpv6Literal`/`toEditable`/`toCanonicalOrNull`/`MAX_IPV6_PREFIX_RULES` (T0) are exactly what T1's screen and the tests reference; `SENTINEL_UID` (T3 Step 2) matches the `appLabel` rewrite (T3 Step 3); string names match across strings.xml, the screen, the section row, and `appLabel`.
- **Known risks:** (1) SettingsScreen.kt budget — the −12/+6 recipe is deterministic; ktlint may force slightly different wrapping on the new section call (still +6 by construction; the move is the offset). (2) The 139-char `else` line in T3 — fallback documented inline. (3) On-device `su` reads intermittent (fact 15) — every read step has a retry/fallback note. (4) CI coverage on this branch (fact 9) — verified at T0 Step 6.
