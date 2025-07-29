namespace DevOnBike.Heimdall.PostQuantumCryptography.Abstractions
{
    /// <summary>
    /// Holds the result of a hybrid encryption operation.
    /// </summary>
    public interface IHybridCiphertext
    {
        /// <summary>
        /// Gets the key encapsulation data for the classical algorithm.
        /// </summary>
        byte[] ClassicalEncapsulation { get; }

        /// <summary>
        /// Gets the key encapsulation data for the post-quantum algorithm.
        /// </summary>
        byte[] PqcEncapsulation { get; }

        /// <summary>
        /// Gets the ciphertext of the actual data, encrypted with a key derived from the combined secrets.
        /// </summary>
        byte[] Ciphertext { get; }

        /// <summary>
        /// Gets the nonce or initialization vector used for the symmetric encryption.
        /// </summary>
        byte[] Nonce { get; }
    }
}

