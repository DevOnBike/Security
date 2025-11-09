using System.Net.Mail;
using System.Text;
using DevOnBike.Heimdall.Cryptography.Abstractions;
using Microsoft.AspNetCore.DataProtection;

namespace DevOnBike.Heimdall.FormatPreservingEncryption
{
    public class EmailFpe : AbstractFormatPreservingEncryption, IFormatPreservingEncryption
    {
        private readonly ISecret _key;

        public EmailFpe(ISecret key) : base(EmailLocalPartAlphabet.Instance)
        {
            _key = key;
        }

        public unsafe string Encrypt(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return text;
            }

            var email = new MailAddress(text);
            using var tweak = new Secret(Encoding.UTF8.GetBytes(email.Host));

            var keyBytes = new byte[_key.Length];
            var tweakBytes = new byte[tweak.Length];

            fixed (byte* __key__ = keyBytes)
            fixed (byte* __tweak__ = tweakBytes)
            {
                using var safeKeyBytes = new SafeByteArray(keyBytes);
                using var safeTweakBytes = new SafeByteArray(tweakBytes);

                _key.Fill(safeKeyBytes);
                tweak.Fill(safeTweakBytes);

                var encrypted = Encrypt(email.User, safeKeyBytes, safeTweakBytes);
                
                return $"{encrypted}@{email.Host}";
            }
        }

        public unsafe string Decrypt(string encrypted)
        {
            if (string.IsNullOrEmpty(encrypted))
            {
                return encrypted;
            }

            var email = new MailAddress(encrypted);
            
            using var tweak = new Secret(Encoding.UTF8.GetBytes(email.Host));

            var keyBytes = new byte[_key.Length];
            var tweakBytes = new byte[tweak.Length];

            fixed (byte* __key__ = keyBytes)
            fixed (byte* __tweak__ = tweakBytes)
            {
                using var safeKeyBytes = new SafeByteArray(keyBytes);
                using var safeTweakBytes = new SafeByteArray(tweakBytes);

                _key.Fill(safeKeyBytes);
                tweak.Fill(safeTweakBytes);

                var decrypted = Decrypt(email.User, safeKeyBytes, safeTweakBytes);
                
                return $"{decrypted}@{email.Host}";
            }
        }
    }
}