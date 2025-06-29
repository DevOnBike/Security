namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    /// <summary>
    /// Represents a generic private key.
    /// </summary>
    public interface IAsymmetricPrivateKey
    {
        /// <summary>
        /// Gets the algorithm name associated with the key (e.g., "EC", "ML-KEM-768").
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Gets the encoded byte representation of the private key.
        /// </summary>
        /// <remarks>
        /// Care should be taken in handling the exposed private key material.
        /// </remarks>
        /// <returns>A byte array containing the private key.</returns>
        byte[] GetEncoded();
    }
}

