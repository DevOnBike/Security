namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    /// <summary>
    /// Represents a generic public key.
    /// </summary>
    public interface IAsymmetricPublicKey
    {
        /// <summary>
        /// Gets the algorithm name associated with the key (e.g., "EC", "ML-KEM-768").
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the encoded byte representation of the public key.
        /// </summary>
        /// <returns>A byte array containing the public key.</returns>
        byte[] Content { get; }
    }
}

