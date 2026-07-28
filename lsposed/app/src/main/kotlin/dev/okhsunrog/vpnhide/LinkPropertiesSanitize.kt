package dev.okhsunrog.vpnhide

import android.net.LinkAddress
import android.net.LinkProperties
import android.net.RouteInfo
import android.os.Bundle
import de.robv.android.xposed.XposedHelpers
import dev.okhsunrog.vpnhide.generated.IfaceLists
import java.net.InetAddress

// The LinkProperties sanitize subtree, extracted from HookEntry (which is on
// a shrink-only line budget): the VPN scrub, the prefix-rewrite pass, and the
// reflection plumbing both stand on. All functions take the recipient uid
// explicitly — in a push-callback dispatch Binder.getCallingUid() is 1000, so
// callers resolve the uid themselves (effectiveCallerUid / extractRecipientUid)
// and pass it down. Reflection failures degrade to "unmodified", never crash.

// Recursively sanitizes mIfaceName + mRoutes + nested mStackedLinks; the
// length and nesting are inherent to walking that object graph by reflection.
// Still private-field-based (unlike sanitizeNetworkCapabilities, which moved
// to public mutators after Android 17 renamed NC's private fields). LP's
// fields are stable so far; if a future Android renames mIfaceName/mRoutes/
// mStackedLinks, migrate this to the public LinkProperties API
// (setInterfaceName(null) / setLinkAddresses / setRoutes / setDnsServers)
// the same way NC was done, and drop LP from the install-time smoke-check.
internal fun sanitizeLinkProperties(
    copy: LinkProperties,
    rewriteUid: Int,
): Boolean {
    var modified = false

    val ifaceName = XposedHelpers.getObjectField(copy, "mIfaceName") as? String
    val isVpnLp = ifaceName != null && IfaceLists.isVpnIface(ifaceName)
    if (isVpnLp) {
        XposedHelpers.setObjectField(copy, "mIfaceName", null)
        modified = true
    }

    // mLinkAddresses (the tunnel's assigned IP) and mDnses (the VPN's DNS
    // servers) carry no interface tag, so they can only be scrubbed when the
    // whole LinkProperties is a VPN one. Leaving them let an app read the
    // VPN's tunnel address / DNS straight back via getLinkAddresses() /
    // getDnsServers(). Clear both for a VPN LP (the routes/iface above are
    // already handled).
    if (isVpnLp) {
        if (clearLinkPropertyList(copy, "mLinkAddresses")) modified = true
        if (clearLinkPropertyList(copy, "mDnses")) modified = true
    } else if (rewriteLinkAddresses(copy, rewriteUid)) {
        // Address rewrite applies to physical ifaces only — a VPN LP has
        // its address list cleared above instead.
        modified = true
    }

    if (sanitizeLinkRoutes(copy)) modified = true
    if (sanitizeStackedLinks(copy, rewriteUid)) modified = true

    return modified
}

/**
 * Replace addresses covered by a prefix-rewrite rule with their configured
 * fake (CGNAT v4 / carrier v6). Gated GLOBALLY (apps + shell), independent
 * of target membership: the native layer shows the same fake to the same
 * uids, so the framework path must agree — any disagreement between read
 * paths inside one app is itself a detection signal.
 */
internal fun rewriteLinkAddresses(
    copy: LinkProperties,
    uid: Int,
): Boolean {
    if (!SystemServerConfigCache.isRewriteUid(uid)) return false
    val rules = SystemServerConfigCache.load().prefixRewriteRules
    if (rules.isEmpty()) return false
    val ifaceName = XposedHelpers.getObjectField(copy, "mIfaceName") as? String ?: return false
    try {
        @Suppress("UNCHECKED_CAST")
        val addrs =
            XposedHelpers.getObjectField(copy, "mLinkAddresses") as? MutableList<LinkAddress>
                ?: return false
        var modified = false
        for (i in addrs.indices) {
            val la = addrs[i]
            val bytes = la.address.address
            val fake = rules.fakeFor(ifaceName, bytes) ?: continue
            if (bytes.contentEquals(fake)) continue // already rewritten
            // The (InetAddress,int) ctor is hidden from the compile stub but
            // present on-device; getByAddress never touches DNS. The on-link
            // prefix length is the interface's own — keep it.
            val ctor = LinkAddress::class.java.getDeclaredConstructor(InetAddress::class.java, Integer.TYPE)
            ctor.isAccessible = true
            addrs[i] = ctor.newInstance(InetAddress.getByAddress(fake), la.prefixLength) as LinkAddress
            modified = true
        }
        return modified
    } catch (t: Throwable) {
        HookLog.e("VpnHide: rewrite mLinkAddresses failed: ${t.message}")
    }
    return false
}

/** Whether the rewrite pass has anything to do for [uid]: gate + rules. */
internal fun rewriteAppliesTo(uid: Int): Boolean =
    SystemServerConfigCache.isRewriteUid(uid) &&
        SystemServerConfigCache.load().prefixRewriteRules.isNotEmpty()

/**
 * Rewrite-only sanitize for callers that are NOT hide targets: the VPN
 * scrub must not run for them (they didn't opt into hiding), but address
 * rewrite must — the native layer already shows them the fake.
 */
internal fun rewriteOnlyValue(
    value: Any?,
    uid: Int,
): Any? =
    when (value) {
        is LinkProperties -> {
            val copy = cloneLinkProperties(value)
            if (rewriteLinkAddresses(copy, uid)) copy else value
        }

        else -> {
            value
        }
    }

/** Rewrite the LinkProperties inside a callback dispatch bundle for an
 * untargeted recipient. Returns true when the bundle changed. */
@Suppress("DEPRECATION")
internal fun rewriteBundleLinkProperties(
    bundle: Bundle,
    uid: Int,
): Boolean {
    val lp = bundle.getParcelable(LinkProperties::class.java.simpleName) as? LinkProperties ?: return false
    val rewritten = rewriteOnlyValue(lp, uid)
    if (rewritten === lp) return false
    bundle.putParcelable(LinkProperties::class.java.simpleName, rewritten as LinkProperties)
    return true
}

/** Remove routes whose interface is a VPN tunnel. Returns true if any went. */
internal fun sanitizeLinkRoutes(copy: LinkProperties): Boolean {
    try {
        @Suppress("UNCHECKED_CAST")
        val routesField = XposedHelpers.getObjectField(copy, "mRoutes") as? MutableList<RouteInfo> ?: return false
        val filtered =
            routesField.filterNot { route ->
                val routeIface = route.`interface`
                routeIface != null && IfaceLists.isVpnIface(routeIface)
            }
        if (filtered.size != routesField.size) {
            routesField.clear()
            routesField.addAll(filtered)
            return true
        }
    } catch (t: Throwable) {
        HookLog.e("VpnHide: failed to sanitize mRoutes: ${t.message}")
    }
    return false
}

/** Recursively sanitize stacked LinkProperties, dropping ones that become
 *  empty VPN tunnels. Returns true if anything changed. */
@Suppress("NestedBlockDepth") // try-inside-for-inside-if-else over the stacked-LP map is structurally unavoidable
internal fun sanitizeStackedLinks(
    copy: LinkProperties,
    rewriteUid: Int,
): Boolean {
    var modified = false
    try {
        @Suppress("UNCHECKED_CAST")
        val stacked = XposedHelpers.getObjectField(copy, "mStackedLinks") as? MutableMap<String, LinkProperties>
        if (stacked != null && stacked.isNotEmpty()) {
            val filtered = LinkedHashMap<String, LinkProperties>()
            for ((key, value) in stacked) {
                val stackedCopy = cloneLinkProperties(value)
                val stackedModified = sanitizeLinkProperties(stackedCopy, rewriteUid)
                val stackedIface = XposedHelpers.getObjectField(stackedCopy, "mIfaceName") as? String
                if (stackedIface == null && stackedCopy.routes.isEmpty()) {
                    if (stackedModified || IfaceLists.isVpnIface(key)) {
                        modified = true
                    } else {
                        filtered[key] = stackedCopy
                    }
                } else {
                    if (stackedModified) modified = true
                    filtered[key] = stackedCopy
                }
            }
            if (filtered.size != stacked.size || modified) {
                stacked.clear()
                stacked.putAll(filtered)
            }
        }
    } catch (t: Throwable) {
        HookLog.e("VpnHide: failed to sanitize mStackedLinks: ${t.message}")
    }
    return modified
}

/** Deep-copy a LinkProperties via its copy constructor, falling back to the
 *  original on any reflection failure. */
internal fun cloneLinkProperties(value: LinkProperties): LinkProperties =
    try {
        val ctor = LinkProperties::class.java.getDeclaredConstructor(LinkProperties::class.java)
        ctor.isAccessible = true
        ctor.newInstance(value) as LinkProperties
    } catch (_: Throwable) {
        value
    }

/** Clear a `MutableList` field on a LinkProperties by reflection; returns
 *  true if it had entries that were removed. */
internal fun clearLinkPropertyList(
    copy: LinkProperties,
    field: String,
): Boolean =
    try {
        val list = XposedHelpers.getObjectField(copy, field) as? MutableList<*>
        if (!list.isNullOrEmpty()) {
            list.clear()
            true
        } else {
            false
        }
    } catch (t: Throwable) {
        HookLog.e("VpnHide: failed to clear $field: ${t.message}")
        false
    }

/** Copy-then-sanitize: returns the sanitized copy, or the original untouched. */
internal fun sanitizedLinkProperties(
    lp: LinkProperties,
    rewriteUid: Int,
): LinkProperties {
    val copy = cloneLinkProperties(lp)
    if (copy === lp) return lp // reflection failed — never mutate the shared original
    return if (sanitizeLinkProperties(copy, rewriteUid)) copy else lp
}
