using DevOnBike.Heimdall.Cryptography.Abstractions;
using Microsoft.AspNetCore.DataProtection;

namespace DevOnBike.Heimdall.FormatPreservingEncryption
{
    public class CreditCardFpe : AbstractFormatPreservingEncryption, IFormatPreservingEncryption
    {
        private readonly ISecret _key;
        private readonly ISecret _tweak;

        public CreditCardFpe(ISecret key, ISecret tweak) : base(DigitsAlphabet.Instance)
        {
            _key = key;
            _tweak = tweak;
        }

        public unsafe string Encrypt(string text)
        {
            var keyBytes = new byte[_key.Length];
            var tweakBytes = new byte[_tweak.Length];

            fixed (byte* __key__ = keyBytes)
            fixed (byte* __tweak__ = tweakBytes)
            {
                using var safeKeyBytes = new SafeByteArray(keyBytes);
                using var safeTweakBytes = new SafeByteArray(tweakBytes);

                _key.Fill(safeKeyBytes);
                _tweak.Fill(safeTweakBytes);

                return Encrypt(text, safeKeyBytes, safeTweakBytes);
            }
        }

        public unsafe string Decrypt(string encrypted)
        {
            var keyBytes = new byte[_key.Length];
            var tweakBytes = new byte[_tweak.Length];

            fixed (byte* __key__ = keyBytes)
            fixed (byte* __tweak__ = tweakBytes)
            {
                using var safeKeyBytes = new SafeByteArray(keyBytes);
                using var safeTweakBytes = new SafeByteArray(tweakBytes);

                _key.Fill(safeKeyBytes);
                _tweak.Fill(safeTweakBytes);

                return Decrypt(encrypted, safeKeyBytes, safeTweakBytes);
            }
        }

    }
}