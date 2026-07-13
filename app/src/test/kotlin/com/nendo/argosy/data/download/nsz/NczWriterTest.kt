package com.nendo.argosy.data.download.nsz

import org.junit.Assert.assertEquals
import org.junit.Test

class NczWriterTest {

    @Test
    fun `clampChunk returns remaining when boundary is far`() {
        assertEquals(65536, NczWriter.clampChunk(65536, 5_000_000_000L))
    }

    @Test
    fun `clampChunk clamps to a near boundary`() {
        assertEquals(100, NczWriter.clampChunk(65536, 100L))
    }

    @Test
    fun `clampChunk does not overflow for sections larger than 2 GiB`() {
        // 28 GiB program NCA (Witcher): (end - pos) far exceeds Int range.
        // A naive (end - pos).toInt() would wrap to 0/negative here.
        val bytesToBoundary = 0x704e7c000L // ~28 GiB
        val n = NczWriter.clampChunk(65536, bytesToBoundary)
        assertEquals(65536, n)
        assert(n > 0) { "chunk size must stay positive for >2GiB sections" }
    }

    @Test
    fun `clampChunk handles boundary distance of exactly 2^32`() {
        // (end - pos) == 4 GiB: naive toInt() would be 0 -> zero-length chunk.
        assertEquals(65536, NczWriter.clampChunk(65536, 1L shl 32))
    }
}
