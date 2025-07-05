using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.Cryptography.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    public sealed class EcdhKeysGenerator : IAsymmetricKeyPairGenerator
    {
        private readonly SecureRandom _random;

        public EcdhKeysGenerator(SecureRandom random)
        {
            _random = random;
        }

        public EcdhKeysGenerator() : this(RecommendedSecureRandom.Instance)
        {
        }

        /// <inheritdoc />
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            var keyPair = GenerateKeyPairCore();
            var publicKey = (ECPublicKeyParameters)keyPair.Public;
            var privateKey = (ECPrivateKeyParameters)keyPair.Private;

            return AsymmetricKeyPair.Create(publicKey, privateKey);
        }

        private AsymmetricCipherKeyPair GenerateKeyPairCore()
        {
            var parameters = new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), _random);
            var generator = GeneratorUtilities.GetKeyPairGenerator("ECDH");

            generator.Init(parameters);

            return generator.GenerateKeyPair();
        }
        
    }
}