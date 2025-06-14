using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using static DevOnBike.Heimdall.Cryptography.ChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    public class BouncyCastleChaCha20Poly1305 : AbstractChaCha20Poly1305, IChaCha20Poly1305
    {
        private readonly IRandom _random;

        public BouncyCastleChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        /// <inheritdoc/>
        public unsafe byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var chacha = CreateCipher();
            var output = new byte[GetEncryptionTotalLength(toEncrypt)];
            var nonce = CreateNonceBuffer();
            var keyBuffer = CreateKeyBuffer();

            fixed (byte* __unused__1 = nonce)
            fixed (byte* __unused__2 = keyBuffer)
            {
                using var safeKey = new SafeByteArray(keyBuffer);
                using var safeNonce = new SafeByteArray(nonce);
                
                key.Fill(keyBuffer);

                _random.Fill(nonce);

                Init(chacha, true, safeKey, safeNonce);

                var result = chacha.DoFinal(toEncrypt); // encrypted + tag
                var encrypted = new ReadOnlySpan<byte>(result, 0, result.Length - TagSizeInBytes);
                var tag = new ReadOnlySpan<byte>(result, result.Length - TagSizeInBytes, TagSizeInBytes);

                FillNonce(output, safeNonce);
                FillTag(output, tag);
                FillData(output, encrypted);
            }

            return output; // nonce + tag + encrypted
        }

        /// <inheritdoc/>
        public unsafe byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var chacha = CreateCipher();
            var nonce = CreateNonceBuffer();
            var tag = CreateTagBuffer();
            var keyBuffer = CreateKeyBuffer();

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

                var encryptedLength = toDecrypt.Length - NonceSizeInBytes - TagSizeInBytes;
                var toProcess = new byte[toDecrypt.Length - NonceSizeInBytes]; // encrypted + tag

                Buffer.BlockCopy(toDecrypt, toDecrypt.Length - encryptedLength, toProcess, 0, encryptedLength); // encrypted
                Buffer.BlockCopy(tag, 0, toProcess, encryptedLength, TagSizeInBytes); // tag

                Init(chacha, false, safeKey, safeNonce);

                return chacha.DoFinal(toProcess);
            }
        }

        private static void Init(IBufferedCipher cipher, bool forEncryption, ReadOnlySpan<byte> key, byte[] nonce)
        {
            cipher.Init(forEncryption, new AeadParameters(new KeyParameter(key), 16 * 8, nonce));
        }

        private static IBufferedCipher CreateCipher()
        {
            return CipherUtilities.GetCipher("CHACHA20_POLY1305");
        }
    }
}