using DevOnBike.Heimdall.PostQuantumComputing.Contracts;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    /// <summary>
    /// An implementation of the ML-KEM (CRYSTALS-Kyber) Key Encapsulation Mechanism using Bouncy Castle.
    /// This class uses the mlkem768 parameter set, which is the NIST primary recommendation.
    /// </summary>
    public sealed class CrystalsKyber : IKeyEncapsulation
    {
        private static readonly MLKemParameters _parameters = MLKemParameters.ml_kem_1024;

        private readonly SecureRandom _secureRandom = new();

        /// <inheritdoc />
        public PqcKeyPair KeyGen()
        {
            var keyGenParameters = new MLKemKeyGenerationParameters(_secureRandom, _parameters);
            var generator = GeneratorUtilities.GetKeyPairGenerator("ML-KEM");

            generator.Init(keyGenParameters);

            var keyPair = generator.GenerateKeyPair();
            var publicKeyParams = (MLKemPublicKeyParameters)keyPair.Public;
            var privateKeyParams = (MLKemPrivateKeyParameters)keyPair.Private;

            return new PqcKeyPair(publicKeyParams.GetEncoded(), privateKeyParams.GetEncoded());
        }

        /// <inheritdoc />
        public KemEncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey)
        {
            var publicKeyParam = MLKemPublicKeyParameters.FromEncoding(_parameters, publicKey.ToArray());
            var encapsulator = new MLKemEncapsulator(_parameters);

            encapsulator.Init(new ParametersWithRandom(publicKeyParam, _secureRandom));

            Span<byte> encapsulation = new byte[encapsulator.EncapsulationLength];
            Span<byte> secret = new byte[encapsulator.SecretLength];

            // Encapsulate the secret using the public key
            encapsulator.Encapsulate(encapsulation, secret);

            return new KemEncapsulationResult(secret.ToArray(), encapsulation.ToArray());
        }

        /// <inheritdoc />
        public byte[] Decapsulate(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> ciphertext)
        {
            var privateKeyParams = MLKemPrivateKeyParameters.FromEncoding(_parameters, privateKey.ToArray());
            var decapsulator = new MLKemDecapsulator(_parameters);

            decapsulator.Init(privateKeyParams);

            Span<byte> secret = new byte[decapsulator.SecretLength];

            decapsulator.Decapsulate(ciphertext, secret);

            return secret.ToArray();
        }
    }
}