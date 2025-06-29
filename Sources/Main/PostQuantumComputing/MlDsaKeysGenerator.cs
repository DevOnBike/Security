using DevOnBike.Heimdall.PostQuantumComputing.Abstractions;
using DevOnBike.Heimdall.PostQuantumComputing.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    public sealed class MlDsaKeysGenerator : IKeysGenerator
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
        public PqcKeyPair GenerateKeyPair()
        {
            var keyPair = GenerateKeyPairCore();
            var publicKey = (MLKemPublicKeyParameters)keyPair.Public;
            var privateKey = (MLKemPrivateKeyParameters)keyPair.Private;

            return new PqcKeyPair(publicKey.GetEncoded(), privateKey.GetEncoded());
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