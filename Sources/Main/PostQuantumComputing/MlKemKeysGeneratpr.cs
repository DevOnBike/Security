using DevOnBike.Heimdall.PostQuantumComputing.Abstractions;
using DevOnBike.Heimdall.PostQuantumComputing.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    public sealed class MlKemKeysGeneratpr : IKeysGenerator
    {
        private readonly MLKemParameters _parameters;
        private readonly SecureRandom _random;

        public MlKemKeysGeneratpr(SecureRandom random, MLKemParameters keyGenerationParameters)
        {
            _random = random;
            _parameters = keyGenerationParameters;
        }

        public MlKemKeysGeneratpr() : this(RecommendedSecureRandom.Instance, MLKemParameters.ml_kem_768)
        {
        }

        /// <inheritdoc />
        public PqcKeyPair GenerateKeyPair()
        {
            var keyPair = GenerateKeyPairCore();
            var publicKey = (MLKemPublicKeyParameters)keyPair.Public;
            var privateKey = (MLKemPrivateKeyParameters)keyPair.Private;

            return new PqcKeyPair(publicKey.GetEncoded(), privateKey.GetEncoded());
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