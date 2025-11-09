using Org.BouncyCastle.Crypto.Utilities;

namespace DevOnBike.Heimdall.Cryptography.FormatPreservingEncryption
{
    public class EmailLocalPartAlphabet : BasicAlphabetMapper
    {
        public static readonly EmailLocalPartAlphabet Instance = new();

        private EmailLocalPartAlphabet() : this("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        {
        }

        protected EmailLocalPartAlphabet(string alphabet) : base(alphabet)
        {
        }
    }
}
