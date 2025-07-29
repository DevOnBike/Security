using DevOnBike.Heimdall.Cryptography;
using DevOnBike.Heimdall.Cryptography.Abstractions;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Security.Cryptography;
using System.Text;
using DevOnBike.Heimdall.PostQuantumCryptography;
using DevOnBike.Heimdall.PostQuantumCryptography.Abstractions;

namespace DevOnBike.Security.Tests.Pqc
{
    public class PqcEnvelopeEncryptionTests
    {
        [Fact]
        public void ShouldEncryptAndDecryptOwnData_UsingPqcEnvelopeEncryption()
        {
            // ARRANGE: One-time setup and data definition

            // 1. Generate long-term master key pairs. In a real app, these would be
            //    generated once and stored securely.
            var ecMasterKeyPair = GenerateEcKeyPair();
            var kyberMasterKeyPair = GenerateKyberKeyPair();

            // 2. Define the data to be encrypted.
            var originalPlaintext = "My data must be safe from quantum computers, haha";

            // ACT: ENCRYPTION FLOW 🔒

            // 1. Generate a new, random Data Encryption Key (DEK) for this session.
            var dataEncryptionKey = GenerateRandomBytes(32); // 256-bit AES key

            // 2. Create a hybrid Key Encryption Key (KEK) to wrap the DEK.
            (var keyEncryptionKey, var encapsulation) = CreateKeyWrappingKey_ForEncryption(
                ecMasterKeyPair,
                kyberMasterKeyPair.Public);

            // 3. Wrap the DEK with the KEK.
            (var wrappedDek, var kekNonce, var tag1) = EncryptPayload(keyEncryptionKey, dataEncryptionKey);

            // 4. Encrypt the actual data using the original DEK.
            (var ciphertext, var dataNonce,var tag2) = EncryptPayload(dataEncryptionKey, Encoding.UTF8.GetBytes(originalPlaintext));

            // At this point, you would store:
            // - ciphertext
            // - wrappedDek
            // - encapsulation
            // - kekNonce
            // - dataNonce
            // You discard the original dataEncryptionKey and keyEncryptionKey.


            // ACT: DECRYPTION FLOW 🔓

            // 1. Regenerate the KEK using your private master keys and the stored encapsulation data.
            var regeneratedKek = CreateKeyWrappingKey_ForDecryption(
                ecMasterKeyPair,
                kyberMasterKeyPair.Private,
                encapsulation);

            // 2. Decrypt the wrapped DEK to recover the original Data Encryption Key.
            var recoveredDek = DecryptPayload(regeneratedKek, wrappedDek, kekNonce, tag1);

            // 3. Decrypt the main ciphertext using the recovered DEK.
            var decryptedPayloadBytes = DecryptPayload(recoveredDek, ciphertext, dataNonce, tag2);
            var decryptedPlaintext = Encoding.UTF8.GetString(decryptedPayloadBytes);

            // ASSERT
            // First, prove the key was recovered correctly.
            Assert.Equal(dataEncryptionKey, recoveredDek);
            // Finally, prove the data was recovered correctly.
            Assert.Equal(originalPlaintext, decryptedPlaintext);
        }

        // --- Cryptographic Helper Methods ---

        // NIST FIPS 186 specifies approved Elliptic Curves. P-256 is a standard choice.
        private IAsymmetricKeyPair GenerateEcKeyPair()
        {
            var generator = new EcdhKeysGenerator();
            return generator.GenerateKeyPair();
        }

        // NIST FIPS 203 standardizes CRYSTALS-Kyber as ML-KEM.
        private IAsymmetricKeyPair GenerateKyberKeyPair()
        {
            var generator = new MlKemKeysGenerator();
            return generator.GenerateKeyPair();
        }

        private byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            new SecureRandom().NextBytes(bytes);
            return bytes;
        }

        // NIST SP 800-56C recommends combining secrets from different schemes using a KDF.
        // A cryptographic hash function like SHA-384 is a simple and effective KDF.
        private (byte[] WrappingKey, byte[] Encapsulation) CreateKeyWrappingKey_ForEncryption(
            IAsymmetricKeyPair classicKeyPair,
            IAsymmetricPublicKey kyberPublicKey)
        {
            // Classical Secret: Perform ECDH with your own key pair.
            var pk = PrivateKeyFactory.CreateKey(classicKeyPair.Private.Content);
            var ecAgreement = new ECDHBasicAgreement();

            ecAgreement.Init(pk);

            var pub = PublicKeyFactory.CreateKey(classicKeyPair.Public.Content);
            var agreementValue = ecAgreement.CalculateAgreement(pub);
            var ecSecret = BigIntegers.AsUnsignedByteArray(ecAgreement.GetFieldSize(), agreementValue);

            // PQC Secret: Encapsulate a secret against your own public Kyber key.
            var kemGenerator = CreateEncapsulation();
            var encapsulationResult = kemGenerator.Encapsulate(kyberPublicKey);
            var kyberSecret = encapsulationResult.SharedSecret;

            // Combine both secrets to derive the final wrapping key.
            var kdf = CreateKdf();
            var combinedKey = new byte[ecSecret.Length + kyberSecret.Length];

            Buffer.BlockCopy(ecSecret, 0, combinedKey, 0, ecSecret.Length);
            Buffer.BlockCopy(kyberSecret, 0, combinedKey, ecSecret.Length, kyberSecret.Length);

            var derivedKey = kdf.DeriveKey(
                combinedKey,
                32, // 32 bytes for AES-256
                Encoding.UTF8.GetBytes("HybridKey"), // Label
                Encoding.UTF8.GetBytes("HybridContext")); // Context

            return (derivedKey, encapsulationResult.Encapsulation);
        }

        private byte[] CreateKeyWrappingKey_ForDecryption(
            IAsymmetricKeyPair ecKeyPair,
            IAsymmetricPrivateKey kyberPrivateKey,
            byte[] encapsulation)
        {
            // Recreate the classical secret.
            var ecAgreement = new ECDHBasicAgreement();
            var pk = PrivateKeyFactory.CreateKey(ecKeyPair.Private.Content);
            ecAgreement.Init(pk);

            var pub = PublicKeyFactory.CreateKey(ecKeyPair.Public.Content);
            var agreementValue = ecAgreement.CalculateAgreement(pub);
            var ecSecret = BigIntegers.AsUnsignedByteArray(ecAgreement.GetFieldSize(), agreementValue);

            // Recreate the PQC secret by decapsulating the stored blob.
            var kemGenerator = CreateEncapsulation();
            var kyberSecret = kemGenerator.Decapsulate(kyberPrivateKey, encapsulation);

            // Combine secrets in the exact same way to get the same final key.
            var kdf = CreateKdf();
            var combinedKey = new byte[ecSecret.Length + kyberSecret.Length];

            Buffer.BlockCopy(ecSecret, 0, combinedKey, 0, ecSecret.Length);
            Buffer.BlockCopy(kyberSecret, 0, combinedKey, ecSecret.Length, kyberSecret.Length);

            return kdf.DeriveKey(
                combinedKey,
                32, // 32 bytes for AES-256
                Encoding.UTF8.GetBytes("HybridKey"), // Label
                Encoding.UTF8.GetBytes("HybridContext")); // Context
        }

        // NIST SP 800-38D specifies AES-GCM for authenticated encryption.
        private (byte[] Ciphertext, byte[] Nonce, byte[] Tag) EncryptPayload(byte[] key, byte[] plaintext)
        {
            var nonce = GenerateRandomBytes(12); // GCM recommended nonce size is 96 bits.
            var ciphertext = new byte[plaintext.Length];

            // Updated constructor to specify the tag size explicitly
            using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize); // Specify tag size explicitly

            var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // 16 bytes

            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            return (ciphertext, nonce, tag);
        }

        private byte[] DecryptPayload(byte[] key, byte[] ciphertext, byte[] nonce, byte[] tag)
        {
            var decryptedBytes = new byte[ciphertext.Length];

            using var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize); // Specify tag size explicitly

            aesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes);

            return decryptedBytes;
        }

        private static IEncapsulation CreateEncapsulation()
        {
            return new CrystalsKyberEncapsulation();
        }

        private static IKeyDerivationFunction CreateKdf()
        {
            return new Sp800108HmacCounterKeyDerivationFunction();
        }
    }
}