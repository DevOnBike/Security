using DevOnBike.Heimdall.Cryptography.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using System;
using System.Security.Cryptography;

namespace DevOnBike.Heimdall.Cryptography.Contracts
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
            if (!privateKey.IsPrivate)
            {
                throw new InvalidOperationException("provided key is public but should be private");
            }

            var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

            return Create(privateKey.Parameters.Name, keyInfo.GetDerEncoded());
        }

        public static AsymmetricPrivateKey Create(ECPrivateKeyParameters privateKey)
        {
            if (!privateKey.IsPrivate)
            {
                throw new InvalidOperationException("provided key is public but should be private");
            }

            var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

            return Create(privateKey.AlgorithmName, keyInfo.GetDerEncoded());
        }

        public void Dispose()
        {
            try
            {
                CryptographicOperations.ZeroMemory(Content);
            }
            catch
            {
                // CA1065: Do not raise exceptions in unexpected locations
            }
        }
    }
}