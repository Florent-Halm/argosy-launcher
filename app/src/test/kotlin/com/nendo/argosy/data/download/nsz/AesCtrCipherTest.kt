package com.nendo.argosy.data.download.nsz

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AesCtrCipherTest {

    @Test
    fun `CTR encrypt then decrypt produces original plaintext`() {
        val key = ByteArray(16) { (it + 1).toByte() }
        val counter = ByteArray(16) { 0 }
        val plaintext = ByteArray(256) { (it * 3).toByte() }

        val cipher1 = AesCtrCipher(key, counter, 0)
        val encrypted = cipher1.process(plaintext)

        assertFalse(
            "Encrypted data should differ from plaintext",
            plaintext.contentEquals(encrypted)
        )

        val cipher2 = AesCtrCipher(key, counter, 0)
        val decrypted = cipher2.process(encrypted)

        assertArrayEquals(
            "Round-trip should recover original plaintext",
            plaintext,
            decrypted
        )
    }

    @Test
    fun `CTR with non-zero initial offset produces different output`() {
        val key = ByteArray(16) { (it + 1).toByte() }
        val counter = ByteArray(16) { 0 }
        val data = ByteArray(64) { 0x42 }

        val cipher0 = AesCtrCipher(key, counter, 0)
        val result0 = cipher0.process(data)

        val cipher1 = AesCtrCipher(key, counter, 0x4000)
        val result1 = cipher1.process(data)

        assertFalse(
            "Different offsets should produce different ciphertext",
            result0.contentEquals(result1)
        )
    }

    @Test
    fun `streaming process matches single-shot process`() {
        val key = ByteArray(16) { (it + 5).toByte() }
        val counter = ByteArray(16) { 0 }
        val data = ByteArray(128) { it.toByte() }

        val cipherFull = AesCtrCipher(key, counter, 0)
        val fullResult = cipherFull.process(data)

        val cipherChunked = AesCtrCipher(key, counter, 0)
        val chunk1 = cipherChunked.process(data, 0, 48)
        val chunk2 = cipherChunked.process(data, 48, 80)

        val chunkedResult = chunk1 + chunk2
        assertArrayEquals(
            "Chunked processing should match single-shot",
            fullResult,
            chunkedResult
        )
    }

    @Test
    fun `IV layout matches NCA reference - nonce high, block index low`() {
        // Known-answer vector generated with pycryptodome (nsz's crypto):
        // AES-CTR(key=00..0f, counter = nonce a0..a7 || (0x4000 >> 4) BE)
        // over 16 zero bytes. Pins the NCA IV layout: nonce in bytes 0..7,
        // absolute-offset block index big-endian in bytes 8..15.
        val key = ByteArray(16) { it.toByte() }
        val counter = ByteArray(16) { i ->
            if (i < 8) (0xA0 + i).toByte() else 0
        }

        val cipher = AesCtrCipher(key, counter, 0x4000)
        val ciphertext = cipher.process(ByteArray(16))

        val expected = byteArrayOf(
            0x8A.toByte(), 0xB9.toByte(), 0x25, 0x72,
            0x8F.toByte(), 0x92.toByte(), 0xF1.toByte(), 0x4C,
            0x4E, 0x38, 0x83.toByte(), 0x83.toByte(),
            0x1A, 0xE7.toByte(), 0x3F, 0x08
        )
        assertArrayEquals(
            "IV layout must match nsz reference implementation",
            expected,
            ciphertext
        )
    }
}
