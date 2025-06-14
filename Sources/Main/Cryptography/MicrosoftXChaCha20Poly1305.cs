using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using static DevOnBike.Heimdall.Cryptography.XChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    /// <summary>
    /// Implements XChaCha20-Poly1305 authenticated encryption using the built-in
    /// System.Security.Cryptography classes available in modern .NET.
    /// </summary>
    public class MicrosoftXChaCha20Poly1305 : AbstractXChaCha20Poly1305, IXChaCha20Poly1305
    {
        private readonly IRandom _random;

        public MicrosoftXChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        public unsafe byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var output = new byte[GetEncryptionTotalLength(toEncrypt)];
            var keyBuffer = CreateKeyBuffer();
            var nonce = CreateNonceBuffer();
            var tag = CreateTagBuffer();
            var subKey = HChaCha20.CreateSubKeyBuffer();

            fixed (byte* __unused__0 = nonce)
            fixed (byte* __unused__1 = keyBuffer)
            fixed (byte* __unused__2 = subKey)
            {
                using var safeNonce = new SafeByteArray(nonce);
                using var safeTag = new SafeByteArray(tag);
                using var safeKey = new SafeByteArray(keyBuffer);
                using var safeSubKey = new SafeByteArray(subKey);

                key.Fill(safeKey);

                // 1. Generate the 24-byte nonce.
                _random.Fill(safeNonce); 

                // 2. Derive the sub-key using HChaCha20.
                HChaCha20.DeriveSubKey(safeKey, new ReadOnlySpan<byte>(safeNonce, 0, 16), safeSubKey.Span);

                // 3. Prepare the 12-byte nonce for the ChaCha20 engine.
                var chaChaNonce = new byte[12];
                Buffer.BlockCopy(safeNonce, 16, chaChaNonce, 4, 8);

                // 4. Encrypt using the built-in ChaCha20Poly1305 class.
                using var chacha = CreateCipher(safeSubKey);

                var encrypted = new byte[toEncrypt.Length];

                chacha.Encrypt(chaChaNonce, toEncrypt, encrypted, tag);

                // 5. Combine into a single payload, [24-byte nonce] + [16-byte tag] + [ciphertext]
                FillNonce(output, safeNonce);
                FillTag(output, safeTag);
                FillData(output, encrypted);

                return output;
            }
        }

        /// <inheritdoc/>
        public unsafe byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var keyBuffer = CreateKeyBuffer();
            var nonce = CreateNonceBuffer();
            var tag = CreateTagBuffer();
            var subKey = HChaCha20.CreateSubKeyBuffer();
            var output = new byte[GetDataLength(toDecrypt)];

            fixed (byte* __unused__0 = nonce)
            fixed (byte* __unused__1 = keyBuffer)
            fixed (byte* __unused__2 = subKey)
            {
                using var safeNonce = new SafeByteArray(nonce);
                using var safeTag = new SafeByteArray(tag);
                using var safeKey = new SafeByteArray(keyBuffer);
                using var safeSubKey = new SafeByteArray(subKey);

                key.Fill(safeKey);

                // 1. Deconstruct the payload: nonce + cipher + tag
                ExtractNonce(toDecrypt, safeNonce);
                ExtractTag(toDecrypt, safeTag);

                // 2. Derive the sub-key using HChaCha20.
                HChaCha20.DeriveSubKey(safeKey, new ReadOnlySpan<byte>(safeNonce, 0, 16), safeSubKey.Span);

                // 3. Prepare the 12-byte nonce for the ChaCha20 engine.
                var chaChaNonce = new byte[12];
                Buffer.BlockCopy(safeNonce, 16, chaChaNonce, 4, 8);

                // 4. Decrypt using the built-in ChaCha20Poly1305 class.
                var encrypted = new byte[output.Length];
                
                ExtractData(toDecrypt, encrypted);
                
                using var chacha = new ChaCha20Poly1305(subKey);
                
                chacha.Decrypt(chaChaNonce, encrypted, tag, output);

                return output;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ChaCha20Poly1305 CreateCipher(ReadOnlySpan<byte> subKey)
        {
            return new ChaCha20Poly1305(subKey);
        }
    }
}
