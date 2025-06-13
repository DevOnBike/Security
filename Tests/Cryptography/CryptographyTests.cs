using DevOnBike.Heimdall.Cryptography;
using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.Text;

namespace DevOnBike.Security.Tests.Cryptography
{
    public class CryptographyTests
    {
        [Fact]
        public void BouncyCastleXChacha_EncryptThenDecrypt_ShouldReturnOriginal_Plaintext()
        {
            // Arrange
            var originalPlaintext = Encoding.UTF8.GetBytes("This is a secret message for XChaCha20-Poly1305!");

            // Act
            var key = CreateXChaChaKey();
            var chacha = CreateBouncyCastleXChaCha20Poly1305();
            var ciphertext = chacha.Encrypt(key, originalPlaintext);
            var decryptedPlaintext = chacha.Decrypt(key, ciphertext);

            // Assert
            Assert.Equal(originalPlaintext, decryptedPlaintext);
        }

        [Fact]
        public void MicrosoftXChaCha_EncryptThenDecrypt_ShouldReturnOriginal_Plaintext()
        {
            // Arrange
            var originalPlaintext = Encoding.UTF8.GetBytes("This is a secret message for XChaCha20-Poly1305!");

            // Act
            var key = CreateXChaChaKey();
            var chacha = CreateMicrosoftXChaCha20Poly1305();
            var ciphertext = chacha.Encrypt(key, originalPlaintext);
            var decryptedPlaintext = chacha.Decrypt(key, ciphertext);

            // Assert
            Assert.Equal(originalPlaintext, decryptedPlaintext);
        }

        [Fact]
        public void Decrypt_With_Tampered_Ciphertext_Should_Throw_InvalidCipherTextException()
        {
            // Arrange
            var originalPlaintext = Encoding.UTF8.GetBytes("Another secret message.");
            var key = CreateXChaChaKey();
            var chacha = CreateBouncyCastleXChaCha20Poly1305();
            var ciphertext = chacha.Encrypt(key, originalPlaintext);

            // Act: Tamper with the encrypted data itself. It's located after the nonce.
            var ciphertextStartIndex = XChaCha20Constants.NonceSizeInBytes;
            if (ciphertext.Length > ciphertextStartIndex)
            {
                ciphertext[ciphertextStartIndex]++; // Modify the first byte of the encrypted data + tag payload
            }

            // Assert: Decryption must fail if the ciphertext is not authentic.
            // Bouncy Castle throws an InvalidCipherTextException for tag verification failures.
            Assert.Throws<InvalidCipherTextException>(() => chacha.Decrypt(key, ciphertext));
        }

        [Fact]
        public void Decrypt_With_Tampered_Nonce_In_Payload_Should_Throw_InvalidCipherTextException()
        {
            // Arrange
            var key = CreateXChaChaKey();
            var chacha = CreateBouncyCastleXChaCha20Poly1305();
            var originalPlaintext = Encoding.UTF8.GetBytes("A message with a tampered nonce.");
            var ciphertext = chacha.Encrypt(key, originalPlaintext);

            // Act: Tamper with the nonce in the combined payload.
            ciphertext[0]++; // Modify the first byte of the nonce

            // Assert
            // Because the nonce is used to derive the subkey, tampering with it
            // will result in the wrong key being used for decryption, causing a tag mismatch.
            Assert.Throws<InvalidCipherTextException>(() => chacha.Decrypt(key, ciphertext));
        }

        [Fact]
        public void Decrypt_With_Wrong_Key_Should_Throw_InvalidCipherTextException()
        {
            // Arrange
            var key = CreateXChaChaKey();
            var chacha = CreateBouncyCastleXChaCha20Poly1305();
            var originalPlaintext = Encoding.UTF8.GetBytes("A message for a specific key.");
            var ciphertext = chacha.Encrypt(key, originalPlaintext);

            // Create a completely different key for decryption.
            var wrongKey = CreateXChaChaKey();

            // Act & Assert: Attempting to decrypt with the wrong key must fail.
            Assert.Throws<InvalidCipherTextException>(() => chacha.Decrypt(wrongKey, ciphertext));
        }

        [Fact]
        public void Encrypt_WithEmptyPlaintext_ShouldSucceed()
        {
            // Arrange
            var key = CreateXChaChaKey();
            var chacha = CreateBouncyCastleXChaCha20Poly1305();
            var emptyPlaintext = Array.Empty<byte>();

            // Act
            var ciphertext = chacha.Encrypt(key, emptyPlaintext);
            var decryptedPlaintext = chacha.Decrypt(key, ciphertext);

            // Assert
            Assert.Equal(emptyPlaintext, decryptedPlaintext);
            // The output should be exactly the size of the nonce + tag
            Assert.Equal(XChaCha20Constants.NonceSizeInBytes + XChaCha20Constants.TagSizeInBytes, ciphertext.Length);
        }

        [Fact]
        public void MicrosoftChaCha20Poly1305_EncryptDecrypt_ShouldReturnOriginalData()
        {
            var random = new BouncyCastleRandom();

            // Generate a random 32-byte (256-bit) key for ChaCha20
            var key = new byte[ChaCha20Constants.KeySizeInBytes];
            random.Fill(key);

            using var secret = new Secret(key);

            IChaCha20Poly1305 cryptor = new MicrosoftChaCha20Poly1305(random);
            var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            var encrypted = cryptor.Encrypt(secret, bytes);
            Assert.True(encrypted.Length ==
                        bytes.Length + ChaCha20Constants.TagSizeInBytes + ChaCha20Constants.NonceSizeInBytes);

            var decrypted = cryptor.Decrypt(secret, encrypted);
            Assert.True(decrypted.SequenceEqual(bytes));
        }

        [Fact]
        public void ChaCha20Poly1305_Compare_ShouldWork()
        {
            var random = new BouncyCastleRandom();

            var key = new byte[ChaCha20Constants.KeySizeInBytes];
            random.Fill(key);

            using var secret = new Secret(key);

            IChaCha20Poly1305 bcProtector = new BouncyCastleChaCha20Poly1305(random);
            IChaCha20Poly1305 msProtector = new MicrosoftChaCha20Poly1305(random);

            var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            var encrypted = bcProtector.Encrypt(secret, bytes);
            var decrypted = msProtector.Decrypt(secret, encrypted);
            Assert.True(decrypted.SequenceEqual(bytes));

            encrypted = msProtector.Encrypt(secret, bytes);
            decrypted = bcProtector.Decrypt(secret, encrypted);

            Assert.True(decrypted.SequenceEqual(bytes));
        }

        private BouncyCastleXChaCha20Poly1305 CreateBouncyCastleXChaCha20Poly1305()
        {
            var random = new DefaultRandom();

            return new BouncyCastleXChaCha20Poly1305(random);
        }

        private MicrosoftXChaCha20Poly1305 CreateMicrosoftXChaCha20Poly1305()
        {
            var random = new DefaultRandom();

            return new MicrosoftXChaCha20Poly1305(random);
        }

        private ISecret CreateXChaChaKey()
        {
            return new Secret(RandomNumberGenerator.GetBytes(XChaCha20Constants.KeySizeInBytes));
        }
    }
}