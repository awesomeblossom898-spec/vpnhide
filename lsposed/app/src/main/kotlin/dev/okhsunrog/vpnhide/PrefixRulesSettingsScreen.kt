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
import androidx.compose.material.icons.filled.Public
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
import dev.okhsunrog.vpnhide.ui.components.PreferenceRow
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
