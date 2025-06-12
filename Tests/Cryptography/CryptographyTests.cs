using System.Security.Cryptography;
using System.Text;
using DevOnBike.Heimdall.Cryptography;
using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;

namespace DevOnBike.Security.Tests.Cryptography
{
    public class CryptographyTests
    {
        [Fact]
        public void Encrypt_ThrowsArgumentException_WhenNonceLengthIsIncorrect()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("test data");
            var shortNonce = GenerateRandomBytes(23); // XChaCha20 nonce must be 24 bytes
            var key = GenerateRandomBytes(32);

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => XChaCha20Poly1305Helper.Encrypt(plaintext, shortNonce, key));
            Assert.Contains("XChaCha20 nonce must be 24 bytes long.", ex.Message);
        }

        [Fact]
        public void Encrypt_ThrowsArgumentException_WhenKeyLengthIsIncorrect()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("test data");
            var nonce = GenerateRandomBytes(24);
            var shortKey = GenerateRandomBytes(31); // Key must be 32 bytes

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, shortKey));
            Assert.Contains("Key must be 32 bytes long.", ex.Message);
        }

        [Fact]
        public void Decrypt_ThrowsArgumentException_WhenNonceLengthIsIncorrect()
        {
            // Arrange
            var encryptedData = GenerateRandomBytes(50); // Dummy data for length check
            var shortNonce = GenerateRandomBytes(23); // XChaCha20 nonce must be 24 bytes
            var key = GenerateRandomBytes(32);

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => XChaCha20Poly1305Helper.Decrypt(encryptedData, shortNonce, key));
            Assert.Contains("XChaCha20 nonce must be 24 bytes long.", ex.Message);
        }

        [Fact]
        public void Decrypt_ThrowsArgumentException_WhenKeyLengthIsIncorrect()
        {
            // Arrange
            var encryptedData = GenerateRandomBytes(50); // Dummy data for length check
            var nonce = GenerateRandomBytes(24);
            var shortKey = GenerateRandomBytes(31); // Key must be 32 bytes

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => XChaCha20Poly1305Helper.Decrypt(encryptedData, nonce, shortKey));
            Assert.Contains("Key must be 32 bytes long.", ex.Message);
        }

        [Fact]
        public void Decrypt_ThrowsArgumentException_WhenEncryptedDataIsTooShort()
        {
            // Arrange
            // Poly1305 tag is 16 bytes. Encrypted data must at least contain the tag.
            var encryptedData = GenerateRandomBytes(15);
            var nonce = GenerateRandomBytes(24);
            var key = GenerateRandomBytes(32);

            // Act & Assert
            var ex = Assert.Throws<ArgumentException>(() => XChaCha20Poly1305Helper.Decrypt(encryptedData, nonce, key));
            Assert.Contains("Encrypted data is too short.", ex.Message);
        }

        // --- Functional Tests (validating flow, not cryptographic strength of placeholder HChaCha20) ---

        [Fact]
        public void EncryptDecrypt_WithValidData_ReturnsOriginalPlaintext()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("This is a secret message for testing.");
            var key = GenerateRandomBytes(32);
            var nonce = GenerateRandomBytes(24);

            // Act
            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, key);
            var decryptedData = XChaCha20Poly1305Helper.Decrypt(encryptedData, nonce, key);

            // Assert
            Assert.NotNull(encryptedData);
            Assert.NotEmpty(encryptedData);
            // The encrypted data length should be plaintext length + 16 (for the tag)
            Assert.Equal(plaintext.Length + 16, encryptedData.Length);

            Assert.NotNull(decryptedData);
            Assert.True(plaintext.SequenceEqual(decryptedData), "decrypted data should match original plaintext");
        }

        [Fact]
        public void EncryptDecrypt_EmptyPlaintext_ReturnsOriginalPlaintext()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("");
            var key = GenerateRandomBytes(32);
            var nonce = GenerateRandomBytes(24);

            // Act
            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, key);
            var decryptedData = XChaCha20Poly1305Helper.Decrypt(encryptedData, nonce, key);

            // Assert
            // For empty plaintext, only the 16-byte Poly1305 tag is returned
            Assert.NotNull(encryptedData);
            Assert.Equal(16, encryptedData.Length); // Only the 16-byte tag

            Assert.NotNull(decryptedData);
            Assert.True(plaintext.SequenceEqual(decryptedData), "decrypted empty plaintext should match original empty plaintext");
        }

        [Fact]
        public void EncryptDecrypt_WithAssociatedData_ReturnsOriginalPlaintext()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("Data that needs confidentiality.");
            var associatedData = Encoding.UTF8.GetBytes("Non-confidential header info or context."); // Associated Data (AAD)
            var key = GenerateRandomBytes(32);
            var nonce = GenerateRandomBytes(24);

            // Act
            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, key, associatedData);
            var decryptedData = XChaCha20Poly1305Helper.Decrypt(encryptedData, nonce, key, associatedData);

            // Assert
            Assert.NotNull(encryptedData);
            Assert.NotEmpty(encryptedData);
            Assert.NotNull(decryptedData);
            Assert.True(plaintext.SequenceEqual(decryptedData), "decrypted data with AAD should match original plaintext");
        }

        [Fact]
        public void Decrypt_WithTamperedCiphertext_ReturnsNull()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("This message will be tampered with.");
            var key = GenerateRandomBytes(32);
            var nonce = GenerateRandomBytes(24);

            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, key);
            Assert.NotNull(encryptedData);

            // Act: Tamper with the ciphertext (first byte of the actual ciphertext part)
            var tamperedEncryptedData = (byte[])encryptedData.Clone();
            // The actual ciphertext starts at index 0 (before the 16-byte tag)
            if (tamperedEncryptedData.Length > 16) // Ensure there's actual ciphertext to tamper with
            {
                tamperedEncryptedData[0] = (byte)(tamperedEncryptedData[0] ^ 0xFF); // Flip a bit
            }
            else // If plaintext was empty, tamper with the tag directly
            {
                tamperedEncryptedData[tamperedEncryptedData.Length - 1] = (byte)(tamperedEncryptedData[tamperedEncryptedData.Length - 1] ^ 0xFF);
            }


            var decryptedData = XChaCha20Poly1305Helper.Decrypt(tamperedEncryptedData, nonce, key);

            // Assert
            // Decryption should fail and return null due to tag mismatch
            Assert.Null(decryptedData);
        }

        [Fact]
        public void Decrypt_WithTamperedTag_ReturnsNull()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("This message's tag will be tampered with.");
            var key = GenerateRandomBytes(32);
            var nonce = GenerateRandomBytes(24);

            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, key);
            Assert.NotNull(encryptedData);

            // Act: Tamper with the tag (last 16 bytes of the encrypted data)
            var tamperedEncryptedData = (byte[])encryptedData.Clone();
            tamperedEncryptedData[tamperedEncryptedData.Length - 1] = (byte)(tamperedEncryptedData[tamperedEncryptedData.Length - 1] ^ 0xFF); // Flip a bit in the last byte of the tag

            var decryptedData = XChaCha20Poly1305Helper.Decrypt(tamperedEncryptedData, nonce, key);

            // Assert
            // Decryption should fail and return null due to tag mismatch
            Assert.Null(decryptedData);
        }

        [Fact]
        public void Decrypt_WithIncorrectNonce_ReturnsNull()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("Message with correct nonce.");
            var key = GenerateRandomBytes(32);
            var originalNonce = GenerateRandomBytes(24);

            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, originalNonce, key);
            Assert.NotNull(encryptedData);

            // Act: Create a different nonce
            var incorrectNonce = GenerateRandomBytes(24);
            while (incorrectNonce.SequenceEqual(originalNonce)) // Ensure it's truly different
            {
                incorrectNonce = GenerateRandomBytes(24);
            }

            var decryptedData = XChaCha20Poly1305Helper.Decrypt(encryptedData, incorrectNonce, key);

            // Assert
            // Decryption should fail because a different nonce will lead to a different subkey/internal nonce
            // for ChaCha20Poly1305, causing a tag mismatch.
            Assert.Null(decryptedData);
        }

        [Fact]
        public void Decrypt_WithIncorrectKey_ReturnsNull()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("Message with correct key.");
            var originalKey = GenerateRandomBytes(32);
            var nonce = GenerateRandomBytes(24);

            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, originalKey);
            Assert.NotNull(encryptedData);

            // Act: Create a different key
            var incorrectKey = GenerateRandomBytes(32);
            while (incorrectKey.SequenceEqual(originalKey)) // Ensure it's truly different
            {
                incorrectKey = GenerateRandomBytes(32);
            }

            var decryptedData = XChaCha20Poly1305Helper.Decrypt(encryptedData, nonce, incorrectKey);

            // Assert
            // Decryption should fail because a different key will lead to a different subkey for ChaCha20Poly1305,
            // causing a tag mismatch.
            Assert.Null(decryptedData);
        }

        [Fact]
        public void Decrypt_WithMissingAssociatedData_ReturnsNull()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("Message encrypted with AAD.");
            var associatedData = Encoding.UTF8.GetBytes("Required-AAD-Info");
            var key = GenerateRandomBytes(32);
            var nonce = GenerateRandomBytes(24);

            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, key, associatedData);
            Assert.NotNull(encryptedData);

            // Act: Try to decrypt without providing associated data (passing null)
            var decryptedData = XChaCha20Poly1305Helper.Decrypt(encryptedData, nonce, key, null);

            // Assert
            // Decryption should fail because the AAD is part of the authentication process.
            Assert.Null(decryptedData);
        }

        [Fact]
        public void Decrypt_WithModifiedAssociatedData_ReturnsNull()
        {
            // Arrange
            var plaintext = Encoding.UTF8.GetBytes("Message encrypted with AAD.");
            var originalAssociatedData = Encoding.UTF8.GetBytes("Required-AAD-Info");
            var modifiedAssociatedData = Encoding.UTF8.GetBytes("Modified-AAD-Info"); // Different AAD
            var key = GenerateRandomBytes(32);
            var nonce = GenerateRandomBytes(24);

            var encryptedData = XChaCha20Poly1305Helper.Encrypt(plaintext, nonce, key, originalAssociatedData);
            Assert.NotNull(encryptedData);

            // Act: Try to decrypt with modified associated data
            var decryptedData = XChaCha20Poly1305Helper.Decrypt(encryptedData, nonce, key, modifiedAssociatedData);

            // Assert
            // Decryption should fail because the AAD is part of the authentication process.
            Assert.Null(decryptedData);
        }
        
        [Fact]
        public void MicrosoftChaCha20Poly1305_EncryptDecrypt_ShouldReturnOriginalData()
        {
            var random = new BouncyCastleRandom();

            // Generate a random 32-byte (256-bit) key for ChaCha20
            var key = new byte[Chacha20Constants.KeySizeInBytes];
            random.Fill(key);

            using var secret = new Secret(key);

            IChaCha20Poly1305 cryptor = new MicrosoftChaCha20Poly1305(random);
            var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            var encrypted = cryptor.Encrypt(secret, bytes);
            Assert.True(encrypted.Length == bytes.Length + Chacha20Constants.TagSizeInBytes + Chacha20Constants.NonceSizeInBytes);

            var decrypted = cryptor.Decrypt(secret, encrypted);
            Assert.True(decrypted.SequenceEqual(bytes));
        }
        
        [Fact]
        public void ChaCha20Poly1305_Compare_ShouldWork()
        {
            var random = new BouncyCastleRandom();

            var key = new byte[Chacha20Constants.KeySizeInBytes];
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

        /// <summary>
        /// Generates an array of cryptographically strong random bytes of a specified length.
        /// </summary>
        /// <param name="length">The desired length of the byte array.</param>
        /// <returns>A new byte array filled with random bytes.</returns>
        private static byte[] GenerateRandomBytes(int length)
        {
            var bytes = new byte[length];
            // Fills a span with a cryptographically strong sequence of random values.
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }
    }
}
