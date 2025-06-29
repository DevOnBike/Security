using DevOnBike.Heimdall.Cryptography.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevOnBike.Heimdall.PostQuantumComputing.Contracts
{
    public class AsymmetricPrivateKey : IAsymmetricPrivateKey
    {
        public string AlgorithmName { get; }

        public byte[] Content { get; }

        private AsymmetricPrivateKey()
        {
        }

        private AsymmetricPrivateKey(string algorithmName, byte[] content)
        {
            AlgorithmName = algorithmName;
            Content = content;
        }

        public static AsymmetricPrivateKey Create(string algorithmName, byte[] content)
        {
            return new AsymmetricPrivateKey(algorithmName, content);
        }

        public static AsymmetricPrivateKey Create(MLKemPrivateKeyParameters privateKey)
        {
            return Create("ML-KEM-768", privateKey.GetEncoded());
        }
    }
}