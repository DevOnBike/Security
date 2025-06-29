using DevOnBike.Heimdall.PostQuantumComputing.Abstractions;
using DevOnBike.Heimdall.PostQuantumComputing.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    /// <summary>
    /// An implementation of the ML-KEM (aka CRYSTALS-Kyber) Key Encapsulation Mechanism using Bouncy Castle.
    /// This class uses the mlkem768 parameter set, which is the NIST primary recommendation.
    /// </summary>
    public sealed class CrystalsKyberEncapsulation : IKeyEncapsulation
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
        public PqcKeyPair GenerateKeyPair()
        {
            var keyPair = GenerateKeyPairCore();
            var publicKey = (MLKemPublicKeyParameters)keyPair.Public;
            var privateKey = (MLKemPrivateKeyParameters)keyPair.Private;

            return new PqcKeyPair(publicKey.GetEncoded(), privateKey.GetEncoded());
        }

        /// <inheritdoc />
        public KemEncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey)
        {
            var publicKeyParam = MLKemPublicKeyParameters.FromEncoding(_parameters, publicKey.ToArray());
            var encapsulator = new MLKemEncapsulator(_parameters);

            encapsulator.Init(new ParametersWithRandom(publicKeyParam, _random));

            Span<byte> encapsulation = new byte[encapsulator.EncapsulationLength];
            Span<byte> secret = new byte[encapsulator.SecretLength];

            // Encapsulate the secret using the public key
            encapsulator.Encapsulate(encapsulation, secret);

            return new KemEncapsulationResult(secret.ToArray(), encapsulation.ToArray());
        }

        /// <inheritdoc />
        public byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> cipherText)
        {
            var decapsulator = new MLKemDecapsulator(_parameters);

            decapsulator.Init(MLKemPrivateKeyParameters.FromEncoding(_parameters, privateKey.ToArray()));

            Span<byte> secret = new byte[decapsulator.SecretLength];

            decapsulator.Decapsulate(cipherText, secret);

            return secret.ToArray();
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