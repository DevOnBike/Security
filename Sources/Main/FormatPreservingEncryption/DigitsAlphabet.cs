using Org.BouncyCastle.Crypto.Utilities;

namespace DevOnBike.Heimdall.FormatPreservingEncryption
{
    public class DigitsAlphabet : BasicAlphabetMapper
    {
        public static readonly DigitsAlphabet Instance = new();

        private DigitsAlphabet() : this("0123456789")
        {
        }

        protected DigitsAlphabet(string alphabet) : base(alphabet)
        {
        }
    }
}
