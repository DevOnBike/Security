using DevOnBike.Heimdall.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace DevOnBike.Security.Tests.FormatPreservingEncryption
{
    public class FpeTests
    {
        [Fact]
        public void CreditCardFpe_EncryptionDecryption()
        {
            var key = Hex.Decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");

            // A tweak is public, non-secret data that changes the encryption output.
            // For example, you could use a customer ID or a portion of the card's BIN.
            var tweak = Encoding.UTF8.GetBytes("some-public-tweak-data");

            var secretKey = new Secret(key);
            var secretTweak = new Secret(tweak);
            var fpe = new CreditCardFpe(secretKey, secretTweak);

            // 3. Define the credit card number to encrypt
            var originalCardNumber = "4242424242424242";

            // 4. Encrypt the number
            var encryptedCardNumber = fpe.Encrypt(originalCardNumber);

            // 5. Decrypt the number
            var decryptedCardNumber = fpe.Decrypt(encryptedCardNumber);

            Assert.Equal(originalCardNumber, decryptedCardNumber);
        }

    }
}