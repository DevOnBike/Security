using DevOnBike.Heimdall.Cryptography.Abstractions;

namespace DevOnBike.Heimdall.PostQuantumComputing.Abstractions
{
    /// <summary>
    /// Defines the contract for a hybrid encryption service.
    /// </summary>
    public interface IHybridEncryptor
    {
        /// <summary>
        /// Encrypts plaintext data using a hybrid scheme involving a classical and a PQC public key.
        /// </summary>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="classicalPublicKey">The recipient's classical public key (e.g., EC).</param>
        /// <param name="pqcPublicKey">The recipient's post-quantum public key (e.g., ML-KEM).</param>
        /// <returns>An object containing the complete hybrid ciphertext.</returns>
        IHybridCiphertext Encrypt(
            byte[] plaintext, 
            IAsymmetricPublicKey classicalPublicKey,
            IAsymmetricPublicKey pqcPublicKey);
    }
}

