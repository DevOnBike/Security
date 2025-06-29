using DevOnBike.Heimdall.Cryptography.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevOnBike.Heimdall.PostQuantumComputing.Contracts
{
    public class AsymmetricPublicKey : IAsymmetricPublicKey
    {
        public string AlgorithmName { get; }

        public byte[] Content { get; }

        private AsymmetricPublicKey()
        {
        }

        private AsymmetricPublicKey(string algorithmName, byte[] content)
        {
            AlgorithmName = algorithmName;
            Content = content;
        }

        public static AsymmetricPublicKey Create(string algorithmName, byte[] content)
        {
            return new AsymmetricPublicKey(algorithmName, content);
        }

        public static AsymmetricPublicKey Create(MLKemPublicKeyParameters publicKey)
        {
            return Create("ML-KEM-768", publicKey.GetEncoded());
        }
    }
}