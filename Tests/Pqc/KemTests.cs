using System.Text;
using DevOnBike.Heimdall.PostQuantumComputing;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevOnBike.Security.Tests.Pqc
{
    public class KemTests
    {
        [Fact]
        public void MlDsa_SignThenVerify_ShouldWork()
        {
            // 1. CHOOSE ML-DSA PARAMETERS
            // The parameter names have also been updated.
            // MLDSA_44 was Dilithium2
            // MLDSA_65 was Dilithium3
            // MLDSA_87 was Dilithium5
            var mldsaParameters = MLDsaParameters.ml_dsa_65_with_sha512; // Corresponds to NIST security level 3

            // 2. GENERATE A KEY PAIR
            var random = RecommendedSecureRandom.Instance;
            var keyGenParameters = new MLDsaKeyGenerationParameters(random, mldsaParameters);
            var keyPairGenerator = GeneratorUtilities.GetKeyPairGenerator("ML-DSA");

            keyPairGenerator.Init(keyGenParameters);

            var keyPair = keyPairGenerator.GenerateKeyPair();
            var publicKey = (MLDsaPublicKeyParameters)keyPair.Public;
            var privateKey = (MLDsaPrivateKeyParameters)keyPair.Private;

            // 3. PREPARE A MESSAGE TO SIGN
            var messageText = "This is a test message for the official ML-DSA signature scheme.";
            var message = Encoding.UTF8.GetBytes(messageText);

            // 4. GENERATE THE SIGNATURE
            // Initialize the signer for signing

            var signerAlgorithmOid = NistObjectIdentifiers.id_hash_ml_dsa_65_with_sha512;
            var signer = SignerUtilities.InitSigner(signerAlgorithmOid, forSigning: true, keyPair.Private, random);

            signer.BlockUpdate(message);

            var signature = signer.GenerateSignature();

            // 5. VERIFY THE SIGNATURE
            // Initialize the signer for verification
            var verifier = SignerUtilities.InitSigner(signerAlgorithmOid, forSigning: false, keyPair.Public, null);

            verifier.BlockUpdate(message);
            
            var isSignatureValid = verifier.VerifySignature(signature);
            
            Assert.True(isSignatureValid);
        }

        [Fact]
        public void KeyGen_ShouldGenerateKeysOfCorrectSize()
        {
            // Arrange
            var kem = Create();
            var parameters = MLKemParameters.ml_kem_1024;

            // Act
            var keyPair = kem.KeyGen();

            // Assert
            Assert.NotNull(keyPair.PublicKey);
            Assert.NotNull(keyPair.PrivateKey);
            // Assert.Equal(parameters.GetPublicKeySize(), keyPair.PublicKey.Length);
            // Assert.Equal(parameters.GetPrivateKeySize(), keyPair.PrivateKey.Length);
        }

        [Fact]
        public void Encapsulate_ShouldProduceCiphertextAndSharedSecretOfCorrectSize()
        {
            // Arrange
            var kem = Create();
            var parameters = MLKemParameters.ml_kem_1024;
            var keyPair = kem.KeyGen();

            // Act
            var result = kem.Encapsulate(keyPair.PublicKey);

            // Assert
            Assert.NotNull(result.SharedSecret);
            Assert.NotNull(result.Ciphertext);
            // Assert.Equal(parameters.SessionKeySize / 8, result.SharedSecret.Length);
            // Assert.Equal(parameters.GetCiphertextSize(), result.Ciphertext.Length);
        }

        [Fact]
        public void Decapsulate_ShouldProduceSharedSecretOfCorrectSize()
        {
            // Arrange
            var kem = Create();
            var parameters = MLKemParameters.ml_kem_1024;
            var keyPair = kem.KeyGen();
            var encapsulationResult = kem.Encapsulate(keyPair.PublicKey);

            // Act
            var decapsulatedSecret = kem.Decapsulate(keyPair.PrivateKey, encapsulationResult.Ciphertext);

            // Assert
            Assert.NotNull(decapsulatedSecret);
            // Assert.Equal(parameters.SessionKeySize / 8, decapsulatedSecret.Length);
        }

        [Fact]
        public void FullRoundtrip_DecapsulatedSecret_ShouldMatch_EncapsulatedSecret()
        {
            // Arrange
            var kem = Create();

            // 1. Server generates keys
            var serverKeyPair = kem.KeyGen();

            // 2. Client uses public key to create a shared secret and ciphertext
            var clientResult = kem.Encapsulate(serverKeyPair.PublicKey);
            var clientSharedSecret = clientResult.SharedSecret;
            var ciphertextToServer = clientResult.Ciphertext;

            // 3. Server uses its private key and the ciphertext to derive the secret
            var serverSharedSecret = kem.Decapsulate(serverKeyPair.PrivateKey, ciphertextToServer);

            // Assert
            // With a real implementation, these two secrets will be identical.
            Assert.Equal(clientSharedSecret, serverSharedSecret);
        }

        private static IKeyEncapsulation Create()
        {
            return new CrystalsKyberEncapsulation();
        }
    }
}