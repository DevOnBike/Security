using System.Security.Cryptography;
using DevOnBike.Heimdall.Cryptography.Abstractions;
using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;

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
                FillTag(output, safeTag);
                FillData(output, encrypted);
            }

            return output; // nonce + tag + encrypted
        }

        /// <inheritdoc/>
        public unsafe byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var nonce = CreateNonceBuffer();
            var tag = CreateTagBuffer();
            var keyBuffer = CreateKeyBuffer();
            var output = new byte[GetDataLength(toDecrypt)];

            fixed (byte* __unused__0 = nonce)
            fixed (byte* __unused__1 = tag)
            fixed (byte* __unused__2 = keyBuffer)
            {
                using var safeTag = new SafeByteArray(tag);
                using var safeNonce = new SafeByteArray(nonce);
                using var safeKey = new SafeByteArray(keyBuffer);

                key.Fill(keyBuffer);

                ExtractNonce(toDecrypt, safeNonce);
                ExtractTag(toDecrypt, safeTag);

                var encrypted = new byte[output.Length];
                
                ExtractData(toDecrypt, encrypted);

                using var chacha = new ChaCha20Poly1305(safeKey);

                chacha.Decrypt(safeNonce, encrypted, safeTag, output);
            }

            return output; // decrypted data only
        }
    }
}