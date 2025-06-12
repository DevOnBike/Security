using System.Security.Cryptography;
using DevOnBike.Heimdall.Randomization;
using Microsoft.AspNetCore.DataProtection;

namespace DevOnBike.Heimdall.Cryptography
{
    public class MicrosoftChaCha20Poly1305 : IChaCha20Poly1305
    {
        private readonly IRandom _random;

        public MicrosoftChaCha20Poly1305(IRandom random)
        {
            _random = random;
        }

        public unsafe byte[] Encrypt(ISecret key, byte[] toEncrypt)
        {
            var nonce = new byte[ChaCha20Constants.NonceSizeInBytes];
            _random.Fill(nonce);
            
            var encrypted = new byte[toEncrypt.Length];
            var tag = new byte[ChaCha20Constants.TagSizeInBytes];
            var keyBytes = new byte[ChaCha20Constants.KeySizeInBytes];
            
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

        public unsafe byte[] Decrypt(ISecret key, byte[] toDecrypt)
        {
            var nonce = new byte[ChaCha20Constants.NonceSizeInBytes];
            Buffer.BlockCopy(toDecrypt, 0, nonce, 0, nonce.Length);
            
            var tag = new byte[ChaCha20Constants.TagSizeInBytes];
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