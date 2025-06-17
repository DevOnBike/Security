namespace DevOnBike.Heimdall.PostQuantumComputing.Contracts
{
    /// <summary>
    /// Represents the result of a KEM encapsulation operation.
    /// </summary>
    public class KemEncapsulationResult
    {
        /// <summary>
        /// Gets the generated shared secret.
        /// </summary>
        public byte[] SharedSecret { get; }
        
        /// <summary>
        /// Gets the encapsulation of the secret, to be sent to the other party.
        /// </summary>
        public byte[] Ciphertext { get; }

        public KemEncapsulationResult(byte[] sharedSecret, byte[] ciphertext)
        {
            SharedSecret = sharedSecret;
            Ciphertext = ciphertext;
        }
    }
}

