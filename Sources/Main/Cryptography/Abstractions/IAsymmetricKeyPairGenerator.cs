namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    /// <summary>
    /// Defines a factory for generating asymmetric key pairs.
    /// This abstracts the initialization and generation process.
    /// </summary>
    public interface IAsymmetricKeyPairGenerator
    {
        /// <summary>
        /// Generates a new asymmetric key pair.
        /// </summary>
        /// <returns>An object implementing IAsymmetricKeyPair.</returns>
        IAsymmetricKeyPair GenerateKeyPair();
    }
}
