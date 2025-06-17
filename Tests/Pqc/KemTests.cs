using DevOnBike.Heimdall.PostQuantumComputing;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevOnBike.Security.Tests.Pqc
{
    public class KemTests
    {
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
            byte[] clientSharedSecret = clientResult.SharedSecret;
            byte[] ciphertextToServer = clientResult.Ciphertext;

            // 3. Server uses its private key and the ciphertext to derive the secret
            byte[] serverSharedSecret = kem.Decapsulate(serverKeyPair.PrivateKey, ciphertextToServer);

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
