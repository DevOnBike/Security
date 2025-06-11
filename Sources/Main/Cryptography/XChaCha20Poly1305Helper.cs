using System.Security.Cryptography;

namespace DevOnBike.Heimdall.Cryptography
{
    public static class XChaCha20Poly1305Helper
    {        
        public static byte[] Encrypt(byte[] plaintext, byte[] xchacha20Nonce, byte[] key, byte[] associatedData = null)
        {
            if (xchacha20Nonce.Length != 24)
                throw new ArgumentException("XChaCha20 nonce must be 24 bytes long.");
            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes long.");

            // 1. Calculate a subkey from the first 16 bytes of the nonce and the key, using HChaCha20.
            var hchachaNoncePrefix = new byte[16];
            Array.Copy(xchacha20Nonce, 0, hchachaNoncePrefix, 0, 16);
            var subkey = HChaCha20(key, hchachaNoncePrefix);

            // 2. Use the subkey and remaining 8 bytes of the nonce (prefixed with 4 NUL bytes)
            //    with AEAD_CHACHA20_POLY1305 as normal.
            var chacha20Nonce = new byte[12]; // 4 NUL bytes + 8 bytes from XChaCha20 nonce
            Array.Copy(xchacha20Nonce, 16, chacha20Nonce, 4, 8); // Copy last 8 bytes of XChaCha20 nonce

            using (var chacha = new ChaCha20Poly1305(subkey))
            {
                var ciphertext = new byte[plaintext.Length];
                var tag = new byte[16]; // Poly1305 tag is 16 bytes

                if (associatedData != null)
                {
                    chacha.Encrypt(chacha20Nonce, plaintext, ciphertext, tag, associatedData);
                }
                else
                {
                    chacha.Encrypt(chacha20Nonce, plaintext, ciphertext, tag);
                }

                // Combine ciphertext and tag for storage/transmission
                var result = new byte[ciphertext.Length + tag.Length];
                Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
                Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
                return result;
            }
        }

        public static byte[] Decrypt(byte[] encryptedData, byte[] xchacha20Nonce, byte[] key, byte[] associatedData = null)
        {
            if (xchacha20Nonce.Length != 24)
                throw new ArgumentException("XChaCha20 nonce must be 24 bytes long.");
            if (key.Length != 32)
                throw new ArgumentException("Key must be 32 bytes long.");
            if (encryptedData.Length < 16) // Ciphertext must at least contain the 16-byte tag
                throw new ArgumentException("Encrypted data is too short.");

            // Separate ciphertext and tag
            var ciphertextLength = encryptedData.Length - 16;
            var ciphertext = new byte[ciphertextLength];
            var tag = new byte[16];
            Buffer.BlockCopy(encryptedData, 0, ciphertext, 0, ciphertextLength);
            Buffer.BlockCopy(encryptedData, ciphertextLength, tag, 0, 16);

            // 1. Calculate a subkey from the first 16 bytes of the nonce and the key, using HChaCha20.
            var hchachaNoncePrefix = new byte[16];
            Array.Copy(xchacha20Nonce, 0, hchachaNoncePrefix, 0, 16);
            var subkey = HChaCha20(key, hchachaNoncePrefix);

            // 2. Use the subkey and remaining 8 bytes of the nonce (prefixed with 4 NUL bytes)
            //    with AEAD_CHACHA20_POLY1305 as normal.
            var chacha20Nonce = new byte[12]; // 4 NUL bytes + 8 bytes from XChaCha20 nonce
            Array.Copy(xchacha20Nonce, 16, chacha20Nonce, 4, 8); // Copy last 8 bytes of XChaCha20 nonce

            using (var chacha = new ChaCha20Poly1305(subkey))
            {
                var decryptedData = new byte[ciphertextLength];
                try
                {
                    if (associatedData != null)
                    {
                        chacha.Decrypt(chacha20Nonce, ciphertext, tag, decryptedData, associatedData);
                    }
                    else
                    {
                        chacha.Decrypt(chacha20Nonce, ciphertext, tag, decryptedData);
                    }
                    return decryptedData;
                }
                catch (CryptographicException)
                {
                    // Tag mismatch or decryption failed
                    return null; // Or throw a more specific exception
                }
            }
        }

        // You would need to implement HChaCha20 according to RFCs (e.g., draft-irtf-cfrg-xchacha).
        // This is a placeholder for the HChaCha20 logic.
        private static byte[] HChaCha20(byte[] key, byte[] noncePrefix)
        {
            // HChaCha20 takes a 32-byte key and the first 16 bytes of the 24-byte nonce.
            // It produces a 32-byte subkey.
            // This is a complex cryptographic primitive and should be implemented carefully
            // or, ideally, used from a well-vetted library.
            // For demonstration, a simplistic (and insecure) placeholder:
            var subkey = new byte[32];

            for (var i = 0; i < 16; i++)
            {
                subkey[i] = (byte)(key[i] ^ noncePrefix[i]);
                subkey[i + 16] = (byte)(key[i + 16] ^ noncePrefix[i]); // In reality, this is not how HChaCha20 works
            }
            return subkey;
        }
    }
}

