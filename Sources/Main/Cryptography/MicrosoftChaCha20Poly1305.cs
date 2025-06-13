using System.Security.Cryptography;
using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;
using static DevOnBike.Heimdall.Cryptography.ChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    public class MicrosoftChaCha20Poly1305 : AbstractChaCha20Poly1305, IChaCha20Poly1305
    {
        private readonly IRandom _random;

        public MicrosoftChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        /// <inheritdoc/>
        public unsafe byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var output = new byte[GetEncryptionTotalLength(toEncrypt)];
            var nonce = CreateNonceBuffer();
            var tag = CreateTagBuffer();
            var keyBuffer = CreateKeyBuffer();
            var encrypted = new byte[toEncrypt.Length];

            fixed (byte* __unused__0 = keyBuffer)
            fixed (byte* __unused__1 = tag)
            fixed (byte* __unused__2 = nonce)
            {
                key.Fill(keyBuffer);

                _random.Fill(nonce);

                using var safeKey = new SafeByteArray(keyBuffer);
                using var safeTag = new SafeByteArray(tag);
                using var safeNonce = new SafeByteArray(nonce);
                using var chacha = new ChaCha20Poly1305(safeKey);

                chacha.Encrypt(safeNonce, toEncrypt, encrypted, safeTag);

                FillNonce(output, safeNonce);
                FillTag(output, tag);
                FillData(output, encrypted);
            }

            return output; // nonce + tag + encrypted
        }

        /// <inheritdoc/>
        public unsafe byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var nonce = new byte[NonceSizeInBytes];
            Buffer.BlockCopy(toDecrypt, 0, nonce, 0, nonce.Length);
            
            var tag = new byte[TagSizeInBytes];
            Buffer.BlockCopy(toDecrypt, nonce.Length, tag, 0, tag.Length);
            
            var encrypted = new byte[toDecrypt.Length - nonce.Length - tag.Length];
            Buffer.BlockCopy(toDecrypt, nonce.Length + tag.Length, encrypted, 0, encrypted.Length);
            
            var output = new byte[encrypted.Length];
            var keyBytes = new byte[key.Length];
            
            fixed (byte* __unused__ = keyBytes)
            {
                key.Fill(keyBytes);
                
                using var safeBytes = new SafeByteArray(keyBytes);
                using var chacha = new ChaCha20Poly1305(safeBytes);

                chacha.Decrypt(nonce, encrypted, tag, output);
            }

            return output;
        }
    }
}