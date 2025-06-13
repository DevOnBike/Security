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
            var nonce = new byte[NonceSizeInBytes];
            _random.Fill(nonce);
            
            var encrypted = new byte[toEncrypt.Length];
            var tag = new byte[TagSizeInBytes];
            var keyBytes = new byte[KeySizeInBytes];
            
            fixed (byte* __unused__ = keyBytes)
            {
                key.Fill(keyBytes);
                
                using var safeBytes = new SafeByteArray(keyBytes);
                using var chacha = new ChaCha20Poly1305(safeBytes);

                chacha.Encrypt(nonce, toEncrypt, encrypted, tag);
            }

            var output = new byte[encrypted.Length + nonce.Length + tag.Length]; 

            Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, output, nonce.Length, tag.Length);
            Buffer.BlockCopy(encrypted, 0, output, nonce.Length + tag.Length, encrypted.Length);

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