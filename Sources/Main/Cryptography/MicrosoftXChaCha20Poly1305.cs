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
    public class MicrosoftXChaCha20Poly1305 : IXChaCha20Poly1305
    {
        private readonly IRandom _random;

        public MicrosoftXChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        public unsafe byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var keyBuffer = CreateKeyBuffer();
            var nonce = CreateNonceBuffer();
            var subKey = HChaCha20.CreateSubKeyBuffer();

            fixed (byte* __unused__0 = nonce)
            fixed (byte* __unused__1 = keyBuffer)
            fixed (byte* __unused__2 = subKey)
            {
                using var safeNonce = new SafeByteArray(nonce);
                using var safeKey = new SafeByteArray(keyBuffer);
                using var safeSubKey = new SafeByteArray(subKey);

                key.Fill(safeKey);

                _random.Fill(safeNonce); // 1. Generate the 24-byte nonce.

                // 2. Derive the sub-key using HChaCha20.
                HChaCha20.DeriveSubKey(safeKey, new ReadOnlySpan<byte>(safeNonce, 0, 16), safeSubKey.Span);

                // 3. Prepare the 12-byte nonce for the ChaCha20 engine.
                var chaChaNonce = new byte[12];
                // The first 4 bytes are 0, the rest is the last part of the original nonce.
                Buffer.BlockCopy(safeNonce, 16, chaChaNonce, 4, 8);

                // 4. Encrypt using the built-in ChaCha20Poly1305 class.
                using var chacha = CreateCipher(safeSubKey);

                var encrypted = new byte[toEncrypt.Length];
                var tag = new byte[TagSizeInBytes];

                chacha.Encrypt(chaChaNonce, toEncrypt, encrypted, tag);

                // 5. Combine into a single payload, [24-byte nonce] + [16-byte tag] + [ciphertext]
                var output = new byte[NonceSizeInBytes + TagSizeInBytes + encrypted.Length];

                Buffer.BlockCopy(nonce, 0, output, 0, NonceSizeInBytes);
                Buffer.BlockCopy(tag, 0, output, NonceSizeInBytes, TagSizeInBytes);
                Buffer.BlockCopy(encrypted, 0, output, NonceSizeInBytes + TagSizeInBytes, encrypted.Length);

                return output;
            }
        }

        public unsafe byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var keyBuffer = CreateKeyBuffer();
            var nonce = CreateNonceBuffer();
            var subKey = HChaCha20.CreateSubKeyBuffer();

            fixed (byte* __unused__0 = nonce)
            fixed (byte* __unused__1 = keyBuffer)
            fixed (byte* __unused__2 = subKey)
            {
                using var safeNonce = new SafeByteArray(nonce);
                using var safeKey = new SafeByteArray(keyBuffer);
                using var safeSubKey = new SafeByteArray(subKey);

                key.Fill(safeKey);

                // 1. Deconstruct the payload.
                Buffer.BlockCopy(toDecrypt, 0, safeNonce, 0, NonceSizeInBytes);

                var tag = new ReadOnlySpan<byte>(toDecrypt, NonceSizeInBytes, TagSizeInBytes);
                var encrypted = new ReadOnlySpan<byte>(toDecrypt, NonceSizeInBytes + TagSizeInBytes, 0);

                // 2. Derive the sub-key using HChaCha20.
                HChaCha20.DeriveSubKey(safeKey, new ReadOnlySpan<byte>(safeNonce, 0, 16), safeSubKey.Span);

                // 3. Prepare the 12-byte nonce for the ChaCha20 engine.
                var chaChaNonce = new byte[12];
                Buffer.BlockCopy(safeNonce, 16, chaChaNonce, 4, 8);

                // 4. Decrypt using the built-in ChaCha20Poly1305 class.
                using var chacha = new ChaCha20Poly1305(subKey);

                var output = new byte[encrypted.Length];
                chacha.Decrypt(chaChaNonce, encrypted, tag, output);

                return output;
            }
        }
                
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ChaCha20Poly1305 CreateCipher(ReadOnlySpan<byte> subKey)
        {
            return new ChaCha20Poly1305(subKey);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] CreateNonceBuffer()
        {
            return new byte[NonceSizeInBytes];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] CreateKeyBuffer()
        {
            return new byte[KeySizeInBytes];
        }
    }
}
