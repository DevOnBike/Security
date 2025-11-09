using DevOnBike.Heimdall.Cryptography.Abstractions;

namespace DevOnBike.Heimdall.PostQuantumCryptography.Abstractions
{
    /// <summary>
    /// Defines the functionality for a Key Encapsulation Mechanism (KEM) sender.
    /// </summary>
    public interface IKeyEncapsulator
    {
        /// <summary>
        /// Generates a shared secret and an encapsulation of that secret for a given public key.
        /// </summary>
        /// <param name="publicKey">The recipient's public key.</param>
        /// <returns>An object containing the shared secret and its encapsulation.</returns>
        IEncapsulationResult Encapsulate(IAsymmetricPublicKey publicKey);
    }
}

