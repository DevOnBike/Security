namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    /// <summary>
    /// Represents a pair of public and private asymmetric keys.
    /// </summary>
    public interface IAsymmetricKeyPair
    {
        /// <summary>
        /// Gets the public key component of the key pair.
        /// </summary>
        IAsymmetricPublicKey Public { get; }

        /// <summary>
        /// Gets the private key component of the key pair.
        /// </summary>
        IAsymmetricPrivateKey Private { get; }
    }
}

