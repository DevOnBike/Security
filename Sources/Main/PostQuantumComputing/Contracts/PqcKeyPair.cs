namespace DevOnBike.Heimdall.PostQuantumComputing.Contracts
{
    /// <summary>
    /// Represents a public/private key pair for a PQC algorithm.
    /// </summary>
    public class PqcKeyPair
    {
        /// <summary>
        /// Gets the public component of the key.
        /// </summary>
        public byte[] PublicKey { get; }

        /// <summary>
        /// Gets the private/secret component of the key.
        /// </summary>
        public byte[] PrivateKey { get; }

        public PqcKeyPair(byte[] publicKey, byte[] privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }
    }
}

