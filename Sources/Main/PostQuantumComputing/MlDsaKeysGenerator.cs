using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.Cryptography.Contracts;
using DevOnBike.Heimdall.PostQuantumComputing.Abstractions;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    public sealed class MlDsaKeysGenerator : IAsymmetricKeyPairGenerator
    {
        private readonly MLDsaParameters _parameters;
        private readonly SecureRandom _random;

        public MlDsaKeysGenerator(SecureRandom random, MLDsaParameters keyGenerationParameters)
        {
            _random = random;
            _parameters = keyGenerationParameters;
        }

        public MlDsaKeysGenerator() : this(RecommendedSecureRandom.Instance, MLDsaParameters.ml_dsa_87_with_sha512)
        {
        }

        /// <inheritdoc />
        public IAsymmetricKeyPair GenerateKeyPair()
        {
            var keyPair = GenerateKeyPairCore();
            var publicKey = (MLKemPublicKeyParameters)keyPair.Public;
            var privateKey = (MLKemPrivateKeyParameters)keyPair.Private;

            return AsymmetricKeyPair.Create(publicKey, privateKey);
        }

        private AsymmetricCipherKeyPair GenerateKeyPairCore()
        {
            var parameters = new MLDsaKeyGenerationParameters(_random, _parameters);
            var generator = GeneratorUtilities.GetKeyPairGenerator("ML-DSA");

            generator.Init(parameters);

            return generator.GenerateKeyPair();
        }
    }
}