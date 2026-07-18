package dev.okhsunrog.vpnhide

import dev.okhsunrog.vpnhide.generated.HookIds
import org.junit.Assert.assertEquals
import org.junit.Test

class HookDiagnosticsTest {
    @Test
    fun `no baseline captured yields n a`() {
        // A baseline that was never captured must read n/a — but this is driven by
        // an explicit hasBaseline flag, NOT by the baseline map being empty (a
        // fresh boot captures a valid but empty baseline).
        assertEquals("n/a", counterDeltaText(current = 5, baseline = 3, hasBaseline = false))
    }

    @Test
    fun `new counter with a captured baseline shows the full count`() {
        assertEquals("+5", counterDeltaText(current = 5, baseline = null, hasBaseline = true))
    }

    @Test
    fun `positive delta is the difference`() {
        assertEquals("+7", counterDeltaText(current = 10, baseline = 3, hasBaseline = true))
    }

    @Test
    fun `a counter that went down reads as reset`() {
        assertEquals("reset", counterDeltaText(current = 2, baseline = 9, hasBaseline = true))
    }

    @Test
    fun `unsigned arithmetic survives values past Long MAX`() {
        // Counters are unsigned; a value beyond Long.MAX_VALUE is stored as a
        // negative Long. Comparisons/subtraction must treat it as unsigned.
        assertEquals(
            "+1",
            counterDeltaText(current = Long.MIN_VALUE + 1, baseline = Long.MIN_VALUE, hasBaseline = true),
        )
        // current=0 (unsigned 0) is below baseline=-1 (unsigned ULong.MAX) → reset.
        assertEquals("reset", counterDeltaText(current = 0, baseline = -1L, hasBaseline = true))
    }

    @Test
    fun `if6_seq_show is owned by the kmod only - KPM has no if_inet6 hook`() {
        // The .ko owns /proc/net/if_inet6 via if6_seq_show; the KPM-owned set
        // (KPM_HOOK_MASK) lacks it. Listing KPM as an owner would print
        // "KPM:missing" for a hook KPM can never install.
        assertEquals(listOf(HookIds.Backend.KMOD), hookOwners(HookIds.Hook.IF6_SEQ_SHOW))
        // A hook KPM does install is still co-owned by both kernel backends.
        assertEquals(
            listOf(HookIds.Backend.KMOD, HookIds.Backend.KPM),
            hookOwners(HookIds.Hook.DEV_IOCTL),
        )
    }
}
