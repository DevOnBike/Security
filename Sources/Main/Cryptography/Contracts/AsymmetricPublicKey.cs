using DevOnBike.Heimdall.Cryptography.Abstractions;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace DevOnBike.Heimdall.Cryptography.Contracts
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
            if (publicKey.IsPrivate)
            {
                throw new InvalidOperationException("provided key is private but should be public");
            }

            var keyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

            return Create(publicKey.Parameters.Name, keyInfo.GetDerEncoded());
        }

        public static AsymmetricPublicKey Create(ECPublicKeyParameters publicKey)
        {
            if (publicKey.IsPrivate)
            {
                throw new InvalidOperationException("provided key is private but should be public");
            }

            var keyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

            return Create(publicKey.AlgorithmName, keyInfo.GetDerEncoded());
        }
    }
}