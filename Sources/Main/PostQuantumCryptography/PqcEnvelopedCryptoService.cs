using System.Security.Cryptography;
using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.PostQuantumCryptography.Abstractions;
using DevOnBike.Heimdall.PostQuantumCryptography.Contracts;
using DevOnBike.Heimdall.Randomization;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace DevOnBike.Heimdall.PostQuantumCryptography
{
    public class PqcEnvelopedCryptoService : IPqcEnvelopedCryptoService
    {
        private readonly IAsymmetricKeyPair _classicKeyPair;
        private readonly IAsymmetricKeyPair _pqcKeyPair;
        private readonly IKeyDerivationFunction _kdf;
        private readonly IEncapsulation _encapsulation;
        private readonly IRandom _random;

        public PqcEnvelopedCryptoService(
            IAsymmetricKeyPair classicKeyPair,
            IAsymmetricKeyPair pqcKeyPair,
            IKeyDerivationFunction kdf,
            IEncapsulation encapsulation,
            IRandom random)
        {
            _classicKeyPair = classicKeyPair;
            _pqcKeyPair = pqcKeyPair;
            _kdf = kdf;
            _encapsulation = encapsulation;
            _random = random;
        }

        public PqcEnvelopedEncryptedData Encrypt(byte[] toEncrypt, byte[] aad)
        {
            // 1. Generate a new, random Data Encryption Key (DEK) for this session.
            var dek = GenerateDataEncryptionKey(); // 256-bit AES key

            // 2. Create a hybrid Key Encryption Key (KEK) to wrap the DEK.
            var (kek, encapsulation) = CreateKeyWrappingKeyForEncryption();

            // 3. Wrap the DEK with the KEK.
            var (wrappedDek, kekNonce, tag1) = Encrypt(kek, dek, aad);

            // 4. Encrypt the actual data using the original DEK.
            var (encrypted, dataNonce, tag2) = Encrypt(dek, toEncrypt, aad);

            return new PqcEnvelopedEncryptedData()
            {
                Encrypted = encrypted,
                DataNonce = dataNonce,
                DataTag = tag2,
                Encapsulation = encapsulation,
                KekNonce = kekNonce,
                KekTag = tag1,
                WrappedDek = wrappedDek,
                Aad = aad
            };
        }

        public byte[] Decrypt(PqcEnvelopedEncryptedData encrypted)
        {
            // 1. Regenerate the KEK using your private master keys and the stored encapsulation data.
            var kek = CreateKeyWrappingKeyForDecryption(encrypted.Encapsulation);

            // 2. Decrypt the wrapped DEK to recover the original Data Encryption Key.
            var dek = Decrypt(kek, encrypted.WrappedDek, encrypted.KekNonce, encrypted.KekTag, encrypted.Aad);

            // 3. Decrypt the main ciphertext using the recovered DEK.
            return Decrypt(dek, encrypted.Encrypted, encrypted.DataNonce, encrypted.DataTag, encrypted.Aad);
        }

        // NIST SP 800-56C recommends combining secrets from different schemes using a KDF.
        // A cryptographic hash function like SHA-384 is a simple and effective KDF.
        protected virtual (byte[] wrappingKey, byte[] encapsulation) CreateKeyWrappingKeyForEncryption()
        {
            // Classical Secret: Perform ECDH with your own key pair.
            var pk = PrivateKeyFactory.CreateKey(_classicKeyPair.Private.Content);
            var ecdhAgreement = new ECDHBasicAgreement();

            ecdhAgreement.Init(pk);

            var pub = PublicKeyFactory.CreateKey(_classicKeyPair.Public.Content);
            var agreementValue = ecdhAgreement.CalculateAgreement(pub);
            var classicSecret = BigIntegers.AsUnsignedByteArray(ecdhAgreement.GetFieldSize(), agreementValue);

            // PQC Secret: Encapsulate a secret against your own public Kyber key.
            var encapsulationResult = _encapsulation.Encapsulate(_pqcKeyPair.Public);
            var pqcSecret = encapsulationResult.SharedSecret;

            // Combine both secrets to derive the final wrapping key.
            var combinedKey = new byte[classicSecret.Length + pqcSecret.Length];

            Buffer.BlockCopy(classicSecret, 0, combinedKey, 0, classicSecret.Length);
            Buffer.BlockCopy(pqcSecret, 0, combinedKey, classicSecret.Length, pqcSecret.Length);

            var derivedKey = DeriveKey(combinedKey);

            return (derivedKey, encapsulationResult.Encapsulation);
        }

        protected virtual byte[] CreateKeyWrappingKeyForDecryption(byte[] encapsulation)
        {
            // Recreate the classical secret.
            var ecdhAgreement = new ECDHBasicAgreement();
            var pk = PrivateKeyFactory.CreateKey(_classicKeyPair.Private.Content);

            ecdhAgreement.Init(pk);

            var pub = PublicKeyFactory.CreateKey(_classicKeyPair.Public.Content);
            var agreementValue = ecdhAgreement.CalculateAgreement(pub);
            var classicSecret = BigIntegers.AsUnsignedByteArray(ecdhAgreement.GetFieldSize(), agreementValue);

            // Recreate the PQC secret by decapsulating the stored blob.
            var pqcSecret = _encapsulation.Decapsulate(_pqcKeyPair.Private, encapsulation);

            // Combine secrets in the exact same way to get the same final key.
            var combinedKey = new byte[classicSecret.Length + pqcSecret.Length];

            Buffer.BlockCopy(classicSecret, 0, combinedKey, 0, classicSecret.Length);
            Buffer.BlockCopy(pqcSecret, 0, combinedKey, classicSecret.Length, pqcSecret.Length);

            return DeriveKey(combinedKey);
        }

        // NIST SP 800-38D specifies AES-GCM for authenticated encryption.
        private (byte[] encrypted, byte[] nonce, byte[] tag) Encrypt(byte[] key, byte[] toEncrypt, byte[] aad)
        {
            var nonce = GenerateRandomBytes(12);
            var encrypted = new byte[toEncrypt.Length];

            using var aesGcm = CreateAesGcm(key);

            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            aesGcm.Encrypt(nonce, toEncrypt, encrypted, tag, aad);

            return (encrypted, nonce, tag);
        }

        private static byte[] Decrypt(byte[] key, byte[] encrypted, byte[] nonce, byte[] tag, byte[] aad)
        {
            var decryptedBytes = new byte[encrypted.Length];

            using var aesGcm = CreateAesGcm(key);

            aesGcm.Decrypt(nonce, encrypted, tag, decryptedBytes, aad);

            return decryptedBytes;
        }

        private static AesGcm CreateAesGcm(byte[] key)
        {
            return new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        }

        protected virtual byte[] DeriveKey(byte[] data)
        {
            return _kdf.DeriveKey(data, 32, "HybridKey"u8, "HybridContext"u8);
        }

        protected virtual byte[] GenerateDataEncryptionKey()
        {
            return GenerateRandomBytes(32); // 256-bit AES key
        }

        protected virtual byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];

            _random.Fill(bytes);

            return bytes;
        }
    }
}