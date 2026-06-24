package dev.okhsunrog.vpnhide

import android.graphics.drawable.Drawable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource

internal data class HidingEntry(
    override val packageName: String,
    override val label: String,
    override val icon: Drawable?,
    override val isSystem: Boolean,
    override val userIds: List<Int> = emptyList(),
    val isVpnProvider: Boolean = false,
    val manuallyHidden: Boolean = false,
    val observer: Boolean = false,
) : TargetEntry {
    val effectivelyHidden get() = isVpnProvider || manuallyHidden
    override val anySelected get() = effectivelyHidden || observer
}

@Composable
fun AppHidingScreen(
    searchQuery: String,
    showSystem: Boolean,
    showRussianOnly: Boolean,
    modifier: Modifier = Modifier,
) {
    TargetPickerScreen(
        searchQuery = searchQuery,
        showSystem = showSystem,
        showRussianOnly = showRussianOnly,
        modifier = modifier,
        helpPrefKey = "apps_hiding",
        helpTitle = stringResource(R.string.hiding_help_title),
        help = {
            Text(
                text = stringResource(R.string.hiding_hint_roles),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = stringResource(R.string.hiding_hint_system),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = stringResource(R.string.hiding_hint_reboot),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        merge = { apps, t, selfPkg ->
            val hidden = t.hiddenPkgs
            val observers = t.observerNames
            var autoFixedConflict = false
            val entries =
                apps
                    .filter { it.packageName != selfPkg }
                    .map { app ->
                        // VPN providers are auto-hidden; they cannot be observers —
                        // being an observer while also in the hidden list causes the
                        // app to strip its own package from PM results on startup,
                        // producing a self-lookup NameNotFoundException and a crash.
                        val rawObserver = !app.isVpnProvider && app.packageName in observers
                        // Preserve manual-hide only for non-VPN packages. Packages
                        // covered by VPN auto-detection don't need a manual flag,
                        // and keeping it would show a stale H toggle on upgrade.
                        val rawManuallyHidden = !app.isVpnProvider && app.packageName in hidden
                        val (finalManuallyHidden, finalObserver) =
                            if (rawManuallyHidden && rawObserver) {
                                autoFixedConflict = true
                                false to true
                            } else {
                                rawManuallyHidden to rawObserver
                            }
                        HidingEntry(
                            packageName = app.packageName,
                            label = app.label,
                            icon = app.icon,
                            isSystem = app.isSystem,
                            userIds = app.userIds,
                            isVpnProvider = app.isVpnProvider,
                            manuallyHidden = finalManuallyHidden,
                            observer = finalObserver,
                        )
                    }
            MergeResult(entries, resaveNeeded = autoFixedConflict)
        },
        countText = { entries, _ ->
            "VPN: ${entries.count { it.isVpnProvider }} · H: ${entries.count { it.manuallyHidden }} · O: ${entries.count { it.observer }}"
        },
        buildSaveCommand = { entries, selfPkg, header ->
            // VPN providers (auto) + manually hidden + self are all written to the
            // hidden list. Self is managed invisibly, never shown in the UI.
            val hiddenPkgs =
                (entries.filter { it.effectivelyHidden }.map { it.packageName } + selfPkg)
                    .distinct()
                    .sorted()
            val observerPkgs = entries.filter { it.observer }.map { it.packageName }.sorted()
            buildHidingSaveCommand(header, hiddenPkgs, observerPkgs)
        },
        successMessage = { entries, res ->
            res.getString(
                R.string.hiding_save_success,
                entries.count { it.effectivelyHidden },
                entries.count { it.observer },
            )
        },
    ) { app, userNames, _, onChange ->
        HidingAppRow(app = app, userNames = userNames, onChange = onChange)
    }
}

private fun buildHidingSaveCommand(
    header: String,
    hiddenPkgs: List<String>,
    observerPkgs: List<String>,
): String {
    val parts = mutableListOf<String>()

    // Hidden list: package names, one per line.
    // Mode 0640 + group=system: system_server reads via the group bit;
    // untrusted apps get EACCES because /data/system/ is mode 0775 (the
    // file's "other" bits decide reachability). Prevents apps from
    // enumerating the hidden-package list to fingerprint vpnhide.
    parts += buildConfigWriteCommand(SS_HIDDEN_PKGS_FILE, header, hiddenPkgs)
    parts += systemDataFilePermsParts(SS_HIDDEN_PKGS_FILE, "640")

    // Observer list: resolved UIDs. Same 0640 root:system rationale.
    if (observerPkgs.isNotEmpty()) {
        parts += buildUidResolverCommand(observerPkgs, SS_OBSERVER_UIDS_FILE)
    } else {
        parts += "echo > $SS_OBSERVER_UIDS_FILE 2>/dev/null"
    }
    parts += systemDataFilePermsParts(SS_OBSERVER_UIDS_FILE, "640")

    return parts.joinToString(" ; ")
}

@Composable
private fun HidingAppRow(
    app: HidingEntry,
    userNames: Map<Int, String>,
    onChange: (HidingEntry) -> Unit,
) {
    TargetRowShell(
        label = app.label,
        packageName = app.packageName,
        icon = app.icon,
        userIds = app.userIds,
        userNames = userNames,
    ) {
        if (app.isVpnProvider) {
            // Auto-detected VPN provider: static non-interactive badge.
            // The app cannot also be an observer — see merge comment above.
            TargetChip(
                label = stringResource(R.string.hiding_chip_vpn_provider),
                enabled = true,
                available = false,
                onClick = {},
            )
        } else {
            // Non-VPN app: manual H and O toggles, mutually exclusive.
            TargetChip(
                label = stringResource(R.string.hiding_chip_hidden),
                enabled = app.manuallyHidden,
                onClick = {
                    val newHidden = !app.manuallyHidden
                    onChange(
                        app.copy(
                            manuallyHidden = newHidden,
                            observer = if (newHidden) false else app.observer,
                        ),
                    )
                },
            )
            TargetChip(
                label = stringResource(R.string.hiding_chip_observer),
                enabled = app.observer,
                onClick = {
                    val newObserver = !app.observer
                    onChange(
                        app.copy(
                            observer = newObserver,
                            manuallyHidden = if (newObserver) false else app.manuallyHidden,
                        ),
                    )
                },
            )
        }
    }
}
