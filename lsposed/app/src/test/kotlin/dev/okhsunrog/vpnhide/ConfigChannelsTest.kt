package dev.okhsunrog.vpnhide

import dev.okhsunrog.vpnhide.generated.HookIds
import org.junit.Assert.assertEquals
import org.junit.Test

class ConfigChannelsTest {
    @Test
    fun `config emits a valid snapshot with the full kernel mask, sorted and deduped`() {
        // Out of order + duplicate UID in → sorted, deduped, full-mask out.
        val wire = ConfigChannels.config(debug = false, uids = listOf(10234, 10001, 10234))
        assertEquals(
            """
            vpnhide 1 config
            debug 0
            target 0x2711 0x20003ff
            target 0x27fa 0x20003ff
            """.trimIndent() + "\n",
            wire,
        )
        // The mask is exactly the generated kernel hook mask.
        assertEquals("0x${HookIds.KERNEL_HOOK_MASK.toString(16)}", "0x20003ff")
    }

    @Test
    fun `config round-trips through the parser`() {
        val wire = ConfigChannels.config(debug = true, uids = listOf(10500))
        val parsed = requireNotNull(Protocol.parseConfig(wire))
        assertEquals(true, parsed.debug)
        assertEquals(listOf(Protocol.Target(10500L, HookIds.KERNEL_HOOK_MASK.toLong())), parsed.targets)
    }

    @Test
    fun `empty target set is still a valid header-only config`() {
        assertEquals("vpnhide 1 config\ndebug 0\n", ConfigChannels.config(debug = false, uids = emptyList()))
    }
}
