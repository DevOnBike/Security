using Microsoft.AspNetCore.DataProtection;

namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    /// <summary>
    /// Defines the contract for an XChaCha20-Poly1305 authenticated encryption implementation.
    /// This variant uses a 192-bit (24-byte) nonce for improved security against nonce reuse.
    /// </summary>
    public interface IXChaCha20Poly1305
    {
        /// <summary>
        /// Encrypts the provided plaintext using the XChaCha20-Poly1305 algorithm.
        /// </summary>
        /// <param name="key">The secret key for encryption.</param>
        /// <param name="toEncrypt">The plaintext data to encrypt.</param>
        /// <returns>A byte array containing the nonce, authentication tag, and ciphertext.</returns>
        byte[] Encrypt(ISecret key, byte[] toEncrypt);

        /// <summary>
        /// Decrypts the provided ciphertext using the XChaCha20-Poly1305 algorithm.
        /// </summary>
        /// <param name="key">The secret key for decryption.</param>
        /// <param name="toDecrypt">A byte array containing the nonce, authentication tag, and ciphertext.</param>
        /// <returns>The original plaintext data.</returns>
        byte[] Decrypt(ISecret key, byte[] toDecrypt);
    }
}