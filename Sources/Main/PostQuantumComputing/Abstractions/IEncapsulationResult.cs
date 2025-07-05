namespace DevOnBike.Heimdall.PostQuantumComputing.Abstractions
{
    /// <summary>
    /// Represents the result of a key encapsulation operation from the sender's side.
    /// </summary>
    public interface IEncapsulationResult
    {
        /// <summary>
        /// Gets the derived shared secret. This should be used to derive an encryption key.
        /// </summary>
        byte[] SharedSecret { get; }

        /// <summary>
        /// Gets the public encapsulation data (ciphertext of the secret) to be sent to the recipient.
        /// </summary>
        byte[] Encapsulation { get; }
    }
}

