using DevOnBike.Heimdall.Cryptography.Abstractions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevOnBike.Heimdall.Cryptography.Contracts
{
    public class AsymmetricKeyPair : IAsymmetricKeyPair
    {
        public IAsymmetricPublicKey Public { get; }

        public IAsymmetricPrivateKey Private { get; }

        private AsymmetricKeyPair()
        {

        }

        private AsymmetricKeyPair(IAsymmetricPublicKey publicKey, IAsymmetricPrivateKey privateKey)
        {
            Public = publicKey;
            Private = privateKey;
        }

        public static AsymmetricKeyPair Create(IAsymmetricPublicKey publicKey, IAsymmetricPrivateKey privateKey)
        {
            return new AsymmetricKeyPair(publicKey, privateKey);
        }

        public static AsymmetricKeyPair Create(MLKemPublicKeyParameters publicKey, MLKemPrivateKeyParameters privateKey)
        {
            var pub = AsymmetricPublicKey.Create(publicKey);
            var priv = AsymmetricPrivateKey.Create(privateKey);

            return new AsymmetricKeyPair(pub, priv);
        }

        public static AsymmetricKeyPair Create(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey)
        {
            var pub = AsymmetricPublicKey.Create(publicKey);
            var priv = AsymmetricPrivateKey.Create(privateKey);

            return new AsymmetricKeyPair(pub, priv);
        }
    }
}

