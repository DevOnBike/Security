using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.PostQuantumCryptography.Abstractions;
using DevOnBike.Heimdall.PostQuantumCryptography.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumCryptography
{
    /// <summary>
    /// An implementation of the ML-KEM (aka CRYSTALS-Kyber) Key Encapsulation Mechanism using Bouncy Castle.
    /// This class uses the mlkem768 parameter set, which is the NIST primary recommendation.
    /// </summary>
    public sealed class CrystalsKyberEncapsulation : IEncapsulation
    {
        private readonly MLKemParameters _parameters;
        private readonly SecureRandom _random;

        public CrystalsKyberEncapsulation(SecureRandom random, MLKemParameters keyGenerationParameters)
        {
            _random = random;
            _parameters = keyGenerationParameters;
        }

        public CrystalsKyberEncapsulation() : this(RecommendedSecureRandom.Instance, MLKemParameters.ml_kem_768)
        {
        }

        /// <inheritdoc />
        public IEncapsulationResult Encapsulate(IAsymmetricPublicKey publicKey)
        {
            var keyInfo = PublicKeyFactory.CreateKey(publicKey.Content);
            var keyParams = (MLKemPublicKeyParameters)keyInfo;
            var encapsulator = KemUtilities.GetEncapsulator(_parameters.Name);

            encapsulator.Init(new ParametersWithRandom(keyParams, _random));

            Span<byte> encapsulation = new byte[encapsulator.EncapsulationLength];
            Span<byte> secret = new byte[encapsulator.SecretLength];

            // Encapsulate the secret using the public key
            encapsulator.Encapsulate(encapsulation, secret);

            return KeyEncapsulationResult.Create(secret.ToArray(), encapsulation.ToArray());
        }

        /// <inheritdoc />
        public byte[] Decapsulate(IAsymmetricPrivateKey privateKey, byte[] encapsulation)
        {
            var keyInfo = PrivateKeyFactory.CreateKey(privateKey.Content);
            var keyParams = (MLKemPrivateKeyParameters)keyInfo;
            var decapsulator = KemUtilities.GetDecapsulator(_parameters.Name);

            decapsulator.Init(new ParametersWithRandom(keyParams, _random));

            Span<byte> secret = new byte[decapsulator.SecretLength];

            decapsulator.Decapsulate(encapsulation, secret);

            return secret.ToArray();
        }
    }
}