using DevOnBike.Heimdall.PostQuantumComputing.Contracts;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    /// <summary>
    /// Defines the contract for a Post-Quantum Key Encapsulation Mechanism (KEM).
    /// A KEM is used to establish a secure shared secret between two parties.
    /// </summary>
    public interface IKeyEncapsulation
    {
        /// <summary>
        /// Generates a new public and private key pair.
        /// </summary>
        /// <returns>A key pair containing the public and private keys.</returns>
        PqcKeyPair KeyGen();

        /// <summary>
        /// Executed by the party that wishes to establish a shared secret.
        /// It uses the recipient's public key to generate a shared secret and
        /// an encapsulation of that secret (the ciphertext).
        /// </summary>
        /// <param name="publicKey">The public key of the recipient.</param>
        /// <returns>A result containing the generated shared secret and the ciphertext to be sent to the recipient.</returns>
        KemEncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey);

        /// <summary>
        /// Executed by the recipient of the ciphertext.
        /// It uses their private key to decapsulate the ciphertext and derive the shared secret.
        /// </summary>
        /// <param name="privateKey">The recipient's private key.</param>
        /// <param name="ciphertext">The encapsulated secret received from the other party.</param>
        /// <returns>The derived shared secret.</returns>
        byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext);
    }
}

