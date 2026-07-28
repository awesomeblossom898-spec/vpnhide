package dev.okhsunrog.vpnhide

import android.os.SystemClock
import dev.okhsunrog.vpnhide.generated.HookIds
import java.io.File

internal data class SystemServerConfig(
    val javaTargetHookMasksByAppId: Map<Int, Long> = emptyMap(),
    val observerAppIds: Set<Int> = emptySet(),
    val hiddenPackages: Set<String> = emptySet(),
    val packageAppIds: Map<String, Int> = emptyMap(),
    val debug: Boolean = false,
    // Address-rewrite rules (v6 rewrite + v4, fakes resolved to bytes at load
    // time). Global scope — gated by uid, not by target membership.
    val prefixRewriteRules: List<PrefixRewriteRule> = emptyList(),
) {
    val javaTargetAppIds: Set<Int>
        get() = javaTargetHookMasksByAppId.keys

    fun shouldHidePackageForCallerAppId(
        packageName: String,
        callerAppId: Int,
    ): Boolean {
        if (packageName !in hiddenPackages) return false
        return packageAppIds[packageName] != callerAppId
    }
}

/**
 * Canonical config reader for hooks running inside system_server.
 *
 * It resolves package names through `/data/system/packages.list`, not
 * PackageManager, because these hooks run in PackageManager/ConnectivityManager
 * call paths. Hook matching uses `callingUid % 100000` so every Android profile
 * for the same appId is covered.
 */
internal object SystemServerConfigCache {
    private const val STAT_CHECK_INTERVAL_MS = 1_000L
    private const val USER_ID_MODULO = 100_000
    private val configFile = File(CANONICAL_CONFIG_FILE)
    private val packagesListFile = File("/data/system/packages.list")

    private data class FileFingerprint(
        val exists: Boolean,
        val lastModified: Long,
        val length: Long,
    )

    private data class Fingerprint(
        val config: FileFingerprint,
        val packagesList: FileFingerprint,
    )

    private data class Cache(
        val fingerprint: Fingerprint,
        val config: SystemServerConfig,
        val nextStatCheckUptimeMs: Long,
    )

    @Volatile private var cache: Cache? = null
    private val lock = Any()

    fun load(): SystemServerConfig {
        val now = SystemClock.uptimeMillis()
        cache?.let { cached ->
            if (now < cached.nextStatCheckUptimeMs) return cached.config
        }

        synchronized(lock) {
            val lockedNow = SystemClock.uptimeMillis()
            cache?.let { cached ->
                if (lockedNow < cached.nextStatCheckUptimeMs) return cached.config
                val fingerprint = fingerprint()
                if (cached.fingerprint == fingerprint) {
                    val refreshed = cached.withNextCheck(lockedNow)
                    cache = refreshed
                    return refreshed.config
                }
            }

            val result = readConfig()
            val loadedFingerprint = fingerprint()
            HookLog.i(
                "VpnHide: system_server config loaded " +
                    "java=${result.javaTargetAppIds.size} observer=${result.observerAppIds.size} " +
                    "hidden=${result.hiddenPackages.size} rewrite=${result.prefixRewriteRules.size} " +
                    "debug=${result.debug}",
            )
            cache = Cache(loadedFingerprint, result, nextStatCheck(lockedNow))
            return result
        }
    }

    fun invalidate() {
        cache = null
    }

    fun isTargetUid(uid: Int): Boolean {
        if (uid < android.os.Process.FIRST_APPLICATION_UID) return false
        return load().javaTargetAppIds.contains(appId(uid))
    }

    fun isHookEnabledForUid(
        uid: Int,
        hook: HookIds.Hook,
    ): Boolean {
        if (uid < android.os.Process.FIRST_APPLICATION_UID) return false
        return load().javaTargetHookMasksByAppId[appId(uid)]?.let { mask ->
            mask and (1L shl hook.id) != 0L
        } == true
    }

    fun appId(uid: Int): Int = uid % USER_ID_MODULO

    /** The address-rewrite gate: GLOBAL, mirroring the kernel reader-uid gate
     * (uid >= 10000 || shell). Per-app gating would let an untargeted app see
     * the fake natively but the real address via LinkProperties — a within-app
     * contradiction, which is itself a detection vector. Root/system see truth. */
    fun isRewriteUid(uid: Int): Boolean = uid >= android.os.Process.FIRST_APPLICATION_UID || uid == android.os.Process.SHELL_UID

    private fun Cache.withNextCheck(now: Long): Cache = copy(nextStatCheckUptimeMs = nextStatCheck(now))

    private fun nextStatCheck(now: Long): Long = now + STAT_CHECK_INTERVAL_MS

    private fun readConfig(): SystemServerConfig =
        try {
            val canonical =
                parseCanonicalConfig(configFile.takeIf(File::isFile)?.readText().orEmpty())
                    ?: return SystemServerConfig()
            val packageAppIds = parsePackagesListAppIds(packagesListFile.takeIf(File::isFile)?.readText().orEmpty())
            val javaTargetHookMasks =
                canonical.apps
                    .mapNotNull { (pkg, app) ->
                        val appId = packageAppIds[pkg] ?: return@mapNotNull null
                        val mask =
                            hookSelectionMask(
                                enabled = app.java,
                                hooks = app.javaHooks,
                                entries = LsposedJavaHookEntries,
                            )
                        if (mask == 0L) null else appId to mask
                    }.toMap()
            val observers =
                canonical.apps
                    .filterValues { it.appHiding }
                    .keys
                    .resolveAppIds(packageAppIds)
            val hidden = canonical.apps.filterValues { it.hidden }.keys
            // Resolve fakes to bytes ONCE here — the hook path only walks
            // pre-parsed rules (PrefixRewriteRule.fakeFor), no string parsing
            // per query.
            val rewriteRules =
                canonical.ipv6PrefixRules.mapNotNull { it.toRewriteRuleOrNull() } +
                    canonical.ipv4Rules.mapNotNull { it.toRewriteRuleOrNull() }
            SystemServerConfig(
                javaTargetHookMasksByAppId = javaTargetHookMasks,
                observerAppIds = observers,
                hiddenPackages = hidden,
                packageAppIds = packageAppIds,
                debug = canonical.debug,
                prefixRewriteRules = rewriteRules,
            )
        } catch (t: Throwable) {
            HookLog.e("VpnHide: failed to read canonical config: ${t.message}")
            SystemServerConfig()
        }

    private fun Set<String>.resolveAppIds(packageAppIds: Map<String, Int>): Set<Int> = mapNotNull(packageAppIds::get).toSet()

    private fun fingerprint(): Fingerprint =
        Fingerprint(
            config = configFile.fingerprint(),
            packagesList = packagesListFile.fingerprint(),
        )

    private fun File.fingerprint(): FileFingerprint =
        try {
            if (!exists()) {
                FileFingerprint(exists = false, lastModified = 0L, length = 0L)
            } else {
                FileFingerprint(exists = true, lastModified = lastModified(), length = length())
            }
        } catch (t: Throwable) {
            HookLog.e("VpnHide: failed to stat ${this.path}: ${t.message}")
            FileFingerprint(exists = false, lastModified = 0L, length = 0L)
        }
}

internal fun parsePackagesListAppIds(raw: String): Map<String, Int> =
    raw
        .lineSequence()
        .mapNotNull { line ->
            val parts = line.trim().split(Regex("\\s+"), limit = 3)
            val pkg = parts.getOrNull(0)?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val appId = parts.getOrNull(1)?.toIntOrNull() ?: return@mapNotNull null
            pkg to appId
        }.toMap()
