namespace DevOnBike.Heimdall.Cryptography
{
    /// <summary>
    /// A pure C# implementation of the HChaCha20 function as specified in RFC 8439, Section 2.3.
    /// This is used to derive a sub-key from the main key and the first part of the nonce.
    /// </summary>
    internal static class HChaCha20
    {
        public static byte[] DeriveSubKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
        {
            if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.", nameof(key));
            if (nonce.Length != 16) throw new ArgumentException("Nonce must be 16 bytes.", nameof(nonce));

            var state = new uint[16];
            state[0] = 0x61707865; // "expa"
            state[1] = 0x3320646e; // "nd 3"
            state[2] = 0x79622d32; // "2-by"
            state[3] = 0x6b206574; // "te k"

            for (var i = 0; i < 8; ++i) state[4 + i] = ReadU32LE(key, i * 4);
            for (var i = 0; i < 4; ++i) state[12 + i] = ReadU32LE(nonce, i * 4);

            var workingState = (uint[])state.Clone();

            for (var i = 0; i < 10; i++)
            {
                QuarterRound(ref workingState[0], ref workingState[4], ref workingState[8], ref workingState[12]);
                QuarterRound(ref workingState[1], ref workingState[5], ref workingState[9], ref workingState[13]);
                QuarterRound(ref workingState[2], ref workingState[6], ref workingState[10], ref workingState[14]);
                QuarterRound(ref workingState[3], ref workingState[7], ref workingState[11], ref workingState[15]);
                QuarterRound(ref workingState[0], ref workingState[5], ref workingState[10], ref workingState[15]);
                QuarterRound(ref workingState[1], ref workingState[6], ref workingState[11], ref workingState[12]);
                QuarterRound(ref workingState[2], ref workingState[7], ref workingState[8], ref workingState[13]);
                QuarterRound(ref workingState[3], ref workingState[4], ref workingState[9], ref workingState[14]);
            }

            var subKey = new byte[32];
            WriteU32LE(subKey, 0, state[0] + workingState[0]);
            WriteU32LE(subKey, 4, state[1] + workingState[1]);
            WriteU32LE(subKey, 8, state[2] + workingState[2]);
            WriteU32LE(subKey, 12, state[3] + workingState[3]);
            WriteU32LE(subKey, 16, state[12] + workingState[12]);
            WriteU32LE(subKey, 20, state[13] + workingState[13]);
            WriteU32LE(subKey, 24, state[14] + workingState[14]);
            WriteU32LE(subKey, 28, state[15] + workingState[15]);

            return subKey;
        }

        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b;
            d ^= a;
            d = (d << 16) | (d >> 16);
            c += d;
            b ^= c;
            b = (b << 12) | (b >> 20);
            a += b;
            d ^= a;
            d = (d << 8) | (d >> 24);
            c += d;
            b ^= c;
            b = (b << 7) | (b >> 25);
        }

        private static uint ReadU32LE(ReadOnlySpan<byte> buffer, int offset)
        {
            return (uint)(buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24));
        }

        private static void WriteU32LE(Span<byte> buffer, int offset, uint value)
        {
            buffer[offset] = (byte)value;
            buffer[offset + 1] = (byte)(value >> 8);
            buffer[offset + 2] = (byte)(value >> 16);
            buffer[offset + 3] = (byte)(value >> 24);
        }
    }
}