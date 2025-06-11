using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace DevOnBike.Security.Tests.FormatPreservingEncryption
{
    public class FpeTests
    {
        [Fact]
        public void BouncyCastleFF1_EncryptionDecryption()
        {
            byte[] key = Hex.Decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");            
            byte[] tweak = Hex.Decode("39383736353433323130");
            char[] input = "01234567890123456".ToCharArray();

            // Create a mapper from our alphabet to indexs
            var alphabetMapper = new BasicAlphabetMapper("0123456789");
            var fpeParams = new FpeParameters(new KeyParameter(key), alphabetMapper.Radix, tweak);
            var engine = new FpeFf1Engine();

            engine.Init(true, fpeParams);

            var bytes = alphabetMapper.ConvertToIndexes(input);
            var r = engine.ProcessBlock(bytes, 0, bytes.Length, bytes, 0);
            var aa = alphabetMapper.ConvertToChars(bytes);
            var encrypted = new string(aa);

            engine = new FpeFf1Engine();

            engine.Init(false, fpeParams);

            bytes = alphabetMapper.ConvertToIndexes(aa);
            r = engine.ProcessBlock(bytes, 0, bytes.Length, bytes, 0);
            aa = alphabetMapper.ConvertToChars(bytes);

            var decrypted = new string(aa);
        }

    }
}