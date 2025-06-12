using System.Runtime.CompilerServices;
using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using static DevOnBike.Heimdall.Cryptography.ChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    public class BouncyCastleChaCha20Poly1305 : IChaCha20Poly1305
    {
        private readonly IRandom _random;

        public BouncyCastleChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        public unsafe byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var chacha = CreateCipher();
            var output = new byte[toEncrypt.Length + NonceSizeInBytes + TagSizeInBytes];
            var nonce = CreateNonceBuffer();
            var keyBuffer = CreateKeyBuffer();

            fixed (byte* __unused__1 = nonce)
            fixed (byte* __unused__2 = keyBuffer)
            {
                key.Fill(keyBuffer);
                _random.Fill(nonce);

                using var safeKeyBytes = new SafeByteArray(keyBuffer);
                using var safeNonceBytes = new SafeByteArray(nonce);

                Init(chacha, true, safeKeyBytes, safeNonceBytes);
                var result = chacha.DoFinal(toEncrypt); // data + tag

                Buffer.BlockCopy(safeNonceBytes, 0, output, 0, NonceSizeInBytes);
                Buffer.BlockCopy(result, 0, output, NonceSizeInBytes + TagSizeInBytes, toEncrypt.Length);
                Buffer.BlockCopy(result, toEncrypt.Length, output, NonceSizeInBytes, TagSizeInBytes);
            }

            return output; // nonce + tag + encrypted
        }

        public unsafe byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var chacha = CreateCipher();
            var nonce = CreateNonceBuffer();
            var tag = new byte[TagSizeInBytes];
            var keyBuffer = new byte[key.Length];
            
            fixed (byte* __unused__0 = nonce)
            fixed (byte* __unused__1 = tag)
            fixed (byte* __unused__2 = keyBuffer)
            {
                using var safeTagBytes = new SafeByteArray(tag);
                using var safeNonceBytes = new SafeByteArray(nonce);
                using var safeKeyBytes = new SafeByteArray(keyBuffer);

                key.Fill(keyBuffer);

                Buffer.BlockCopy(toDecrypt, 0, safeNonceBytes, 0, NonceSizeInBytes); // nonce
                Buffer.BlockCopy(toDecrypt, NonceSizeInBytes, safeTagBytes, 0, TagSizeInBytes); // tag

                var encryptedLength = toDecrypt.Length - NonceSizeInBytes - TagSizeInBytes;
                var toProcess = new byte[toDecrypt.Length - NonceSizeInBytes]; // data + tag

                Buffer.BlockCopy(toDecrypt, toDecrypt.Length - encryptedLength, toProcess, 0, encryptedLength);
                Buffer.BlockCopy(tag, 0, toProcess, encryptedLength, TagSizeInBytes);

                Init(chacha, false, safeKeyBytes, safeNonceBytes);

                return chacha.DoFinal(toProcess);
            }
        }

        private static void Init(IBufferedCipher cipher, bool forEncryption, ReadOnlySpan<byte> key, byte[] nonce)
        {
            cipher.Init(forEncryption, new AeadParameters(new KeyParameter(key), 16 * 8, nonce, null));
        }

        private static IBufferedCipher CreateCipher()
        {
            return CipherUtilities.GetCipher("CHACHA20_POLY1305");
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