using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Parameters;

namespace DevOnBike.Heimdall.FormatPreservingEncryption
{
    public abstract class AbstractFormatPreservingEncryption
    {
        protected readonly IAlphabetMapper Alphabet;

        protected AbstractFormatPreservingEncryption(IAlphabetMapper alphabet)
        {
            Alphabet = alphabet;
        }

        protected virtual string Encrypt(string text, ReadOnlySpan<byte> key, byte[] tweak)
        {
            return Execute(text, key, tweak, true);
        }

        protected virtual string Decrypt(string encrypted, ReadOnlySpan<byte> key, byte[] tweak)
        {
            return Execute(encrypted, key, tweak, false);
        }

        protected virtual string Execute(string text, ReadOnlySpan<byte> key, byte[] tweak, bool forEncryption)
        {
            var bytes = Alphabet.ConvertToIndexes(text.ToCharArray());
            var parameters = CreateParameters(key, tweak);
            var engine = CreateEngine(parameters, forEncryption);

            engine.ProcessBlock(bytes, 0, bytes.Length, bytes, 0);

            var output = Alphabet.ConvertToChars(bytes);

            return new string(output);
        }

        protected virtual FpeParameters CreateParameters(ReadOnlySpan<byte> key, byte[] tweak)
        {
            return new FpeParameters(new KeyParameter(key), Alphabet.Radix, tweak);
        }

        protected virtual FpeEngine CreateEngine(FpeParameters parameters, bool forEncryption)
        {
            var engine = CreateEngine();

            engine.Init(forEncryption, parameters);

            return engine;
        }

        protected virtual FpeEngine CreateEngine()
        {
            return new FpeFf1Engine();
        }
    }
}
