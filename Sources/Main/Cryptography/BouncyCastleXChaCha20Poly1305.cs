using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevOnBike.Heimdall.Cryptography
{
    /// <summary>
    /// Implements XChaCha20-Poly1305 authenticated encryption using the Bouncy Castle library.
    /// </summary>
    public class BouncyCastleXChaCha20Poly1305 : IXChaCha20Poly1305
    {
        private readonly IRandom _random;

        public BouncyCastleXChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        public byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var keyBytes = new byte[XChaCha20Constants.KeySizeInBytes]; // No ambiguity now
            key.Fill(keyBytes);

            // 1. Generate the 24-byte nonce.
            var nonce = new byte[XChaCha20Constants.NonceSizeInBytes];
            _random.Fill(nonce);

            // 2. Derive the sub-key using HChaCha20.
            var hChaChaNonce = new ReadOnlySpan<byte>(nonce, 0, 16);
            var subKey = HChaCha20.DeriveSubKey(keyBytes, hChaChaNonce);

            // 3. Prepare the 12-byte nonce for the ChaCha20 engine.
            var chaChaNonce = new byte[12];
            // The first 4 bytes are 0, the rest is the last part of the original nonce.
            Buffer.BlockCopy(nonce, 16, chaChaNonce, 4, 8);

            // 4. Encrypt using Bouncy Castle's standard engine.
            var cipher = new ChaCha20Poly1305();
            var parameters = new AeadParameters(new KeyParameter(subKey), XChaCha20Constants.TagSizeInBytes * 8, chaChaNonce);
            cipher.Init(true, parameters);

            var ciphertext = new byte[cipher.GetOutputSize(toEncrypt.Length)];
            var len = cipher.ProcessBytes(toEncrypt, 0, toEncrypt.Length, ciphertext, 0);
            cipher.DoFinal(ciphertext, len);

            // 5. Combine into a single payload: nonce + ciphertext (which includes the tag)
            var output = new byte[XChaCha20Constants.NonceSizeInBytes + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, output, 0, XChaCha20Constants.NonceSizeInBytes);
            Buffer.BlockCopy(ciphertext, 0, output, XChaCha20Constants.NonceSizeInBytes, ciphertext.Length);

            // Clear sensitive data
            Array.Clear(keyBytes, 0, keyBytes.Length);
            Array.Clear(subKey, 0, subKey.Length);

            return output;
        }

        public byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var keyBytes = new byte[XChaCha20Constants.KeySizeInBytes];
            key.Fill(keyBytes);

            // 1. Deconstruct the payload.
            var nonce = new byte[XChaCha20Constants.NonceSizeInBytes];
            Buffer.BlockCopy(toDecrypt, 0, nonce, 0, XChaCha20Constants.NonceSizeInBytes);

            var ciphertextWithTag = new byte[toDecrypt.Length - XChaCha20Constants.NonceSizeInBytes];
            Buffer.BlockCopy(toDecrypt, XChaCha20Constants.NonceSizeInBytes, ciphertextWithTag, 0, ciphertextWithTag.Length);

            // 2. Derive the sub-key using HChaCha20.
            var hChaChaNonce = new ReadOnlySpan<byte>(nonce, 0, 16);
            var subKey = HChaCha20.DeriveSubKey(keyBytes, hChaChaNonce);

            // 3. Prepare the 12-byte nonce for the ChaCha20 engine.
            var chaChaNonce = new byte[12];
            Buffer.BlockCopy(nonce, 16, chaChaNonce, 4, 8);

            // 4. Decrypt using Bouncy Castle's engine.
            var cipher = new ChaCha20Poly1305();
            var parameters = new AeadParameters(new KeyParameter(subKey), XChaCha20Constants.TagSizeInBytes * 8, chaChaNonce);
            cipher.Init(false, parameters);

            var plaintext = new byte[cipher.GetOutputSize(ciphertextWithTag.Length)];
            var len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, plaintext, 0);
            cipher.DoFinal(plaintext, len);

            // Clear sensitive data
            Array.Clear(keyBytes, 0, keyBytes.Length);
            Array.Clear(subKey, 0, subKey.Length);

            return plaintext;
        }        
    }
}
