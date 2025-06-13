using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Runtime.CompilerServices;
using static DevOnBike.Heimdall.Cryptography.XChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    /// <summary>
    /// Implements XChaCha20-Poly1305 authenticated encryption using the Bouncy Castle library.
    /// </summary>
    public class BouncyCastleXChaCha20Poly1305 : AbstractXChaCha20Poly1305, IXChaCha20Poly1305
    {
        private readonly IRandom _random;

        public BouncyCastleXChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        /// <inheritdoc/>
        public unsafe byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var chacha = CreateCipher();
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

                // 4. Encrypt using Bouncy Castle's engine.
                Init(chacha, true, safeSubKey, chaChaNonce);
                var result = chacha.DoFinal(toEncrypt);

                var tag = result[(result.Length - TagSizeInBytes)..TagSizeInBytes];

                // 5. Combine into a single payload: nonce + cipher text (which includes the tag)
                var output = new byte[NonceSizeInBytes + result.Length];

                Buffer.BlockCopy(safeNonce, 0, output, 0, NonceSizeInBytes);
                Buffer.BlockCopy(result, 0, output, NonceSizeInBytes, result.Length);

                return output; // nonce + cipher + tag
            }
        }

        /// <inheritdoc/>
        public unsafe byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var chacha = CreateCipher();
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

                var toProcess = new byte[toDecrypt.Length - NonceSizeInBytes];
                Buffer.BlockCopy(toDecrypt, NonceSizeInBytes, toProcess, 0, toProcess.Length);

                // 2. Derive the sub-key using HChaCha20.
                HChaCha20.DeriveSubKey(safeKey, new ReadOnlySpan<byte>(safeNonce, 0, 16), safeSubKey.Span);

                // 3. Prepare the 12-byte nonce for the ChaCha20 engine.
                var chaChaNonce = new byte[12];
                Buffer.BlockCopy(safeNonce, 16, chaChaNonce, 4, 8);

                // 4. Decrypt using Bouncy Castle's engine.
                Init(chacha, false, safeSubKey, chaChaNonce);

                return chacha.DoFinal(toProcess);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static IBufferedCipher CreateCipher()
        {
            return CipherUtilities.GetCipher("CHACHA20_POLY1305");
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Init(IBufferedCipher cipher, bool forEncryption, ReadOnlySpan<byte> subKey, byte[] nonce)
        {
            cipher.Init(forEncryption, new AeadParameters(new KeyParameter(subKey), TagSizeInBytes * 8, nonce));
        }
    }
}
