package com.nendo.argosy.data.download.nsz

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Streaming AES-128-CTR cipher for NCZ section re-encryption.
 *
 * NCZ sections with cryptoType 3 or 4 store their data as plaintext
 * after zstd decompression. The original NCA had these sections encrypted
 * with AES-128-CTR. We must re-encrypt them to produce a valid NCA.
 *
 * The IV follows the NCA AES-CTR layout used by nsz's reference
 * implementation: the section counter's upper 8 bytes are the nonce
 * (bytes 0..7), and the block index — the absolute NCA offset / 16 —
 * is written big-endian into the lower 8 bytes (bytes 8..15).
 */
class AesCtrCipher(
    key: ByteArray,
    counter: ByteArray,
    initialOffset: Long
) {
    private val cipher: Cipher

    init {
        require(key.size == 16) { "AES-128-CTR requires 16-byte key" }
        require(counter.size == 16) { "CTR counter must be 16 bytes" }

        val iv = counter.copyOf()
        val blockNumber = initialOffset / 16
        for (i in 15 downTo 8) {
            iv[i] = ((blockNumber ushr ((15 - i) * 8)) and 0xFF).toByte()
        }

        cipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
            init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, "AES"),
                IvParameterSpec(iv)
            )
        }
    }

    fun process(data: ByteArray): ByteArray =
        if (data.isEmpty()) data else cipher.update(data)

    // Cipher.update() returns null (not empty) for zero-length input on some
    // providers; guard so a zero-length chunk can never NPE.
    fun process(data: ByteArray, offset: Int, length: Int): ByteArray =
        if (length == 0) ByteArray(0) else cipher.update(data, offset, length)
}
