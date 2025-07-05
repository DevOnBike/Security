using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.Cryptography.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    public sealed class MlKemKeysGenerator : IAsymmetricKeyPairGenerator
    {
        private readonly MLKemParameters _parameters;
        private readonly SecureRandom _random;

        public MlKemKeysGenerator(SecureRandom random, MLKemParameters keyGenerationParameters)
        {
            _random = random;
            _parameters = keyGenerationParameters;
        }

        public MlKemKeysGenerator() : this(RecommendedSecureRandom.Instance, MLKemParameters.ml_kem_768)
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
            var parameters = new MLKemKeyGenerationParameters(_random, _parameters);
            var generator = GeneratorUtilities.GetKeyPairGenerator("ML-KEM");

            generator.Init(parameters);

            return generator.GenerateKeyPair();
        }
        
    }
}