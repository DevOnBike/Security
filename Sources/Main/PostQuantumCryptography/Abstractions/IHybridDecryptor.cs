using DevOnBike.Heimdall.Cryptography.Abstractions;

namespace DevOnBike.Heimdall.PostQuantumCryptography.Abstractions
{
    /// <summary>
    /// Defines the contract for a hybrid decryption service.
    /// </summary>
    public interface IHybridDecryptor
    {
        /// <summary>
        /// Decrypts a hybrid ciphertext using the recipient's private keys.
        /// </summary>
        /// <param name="hybridCiphertext">The hybrid ciphertext object.</param>
        /// <param name="classicalPrivateKey">The recipient's classical private key.</param>
        /// <param name="pqcPrivateKey">The recipient's post-quantum private key.</param>
        /// <returns>The original plaintext data.</returns>
        byte[] Decrypt(
            IHybridCiphertext hybridCiphertext, 
            IAsymmetricPrivateKey classicalPrivateKey,
            IAsymmetricPrivateKey pqcPrivateKey);
    }
}

