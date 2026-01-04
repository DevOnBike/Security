using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using static DevOnBike.Heimdall.Cryptography.XChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    internal static class HChaCha20
    {
        public static byte[] CreateSubKeyBuffer()
        {
            return new byte[SubKeySizeInBytes];
        }

        public static byte[] DeriveSubKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
        {
            var subKey = new byte[SubKeySizeInBytes];

            DeriveSubKey(key, nonce, subKey);

            return subKey;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void DeriveSubKey(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> subKey)
        {
            if (key.Length != 32)
            {
                throw new ArgumentException("Key must be 32 bytes.", nameof(key));
            }

            if (nonce.Length < 16)
            {
                throw new ArgumentException("Nonce must be at least 16 bytes.", nameof(nonce));
            }

            if (subKey.Length != 32)
            {
                throw new ArgumentException("SubKey buffer must be 32 bytes.", nameof(subKey));
            }

            Span<uint> state = stackalloc uint[16];

            state[0] = 0x61707865; // "expa"
            state[1] = 0x3320646e; // "nd 3"
            state[2] = 0x79622d32; // "2-by"
            state[3] = 0x6b206574; // "te k"

            state[4] = BinaryPrimitives.ReadUInt32LittleEndian(key[..4]);
            state[5] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4));
            state[6] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4));
            state[7] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4));
            state[8] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
            state[9] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4));
            state[10] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4));
            state[11] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4));
            state[12] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[..4]);
            state[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4));
            state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4));
            state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(12, 4));

            for (var i = 0; i < 10; i++)
            {
                // Odd round (Column)
                QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);
                QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);
                QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]);
                QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]);

                // Even round (Diagonal)
                QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]);
                QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]);
                QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);
                QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);
            }

            WriteU32LE(subKey, 0, state[0]);
            WriteU32LE(subKey, 4, state[1]);
            WriteU32LE(subKey, 8, state[2]);
            WriteU32LE(subKey, 12, state[3]);

            WriteU32LE(subKey, 16, state[12]);
            WriteU32LE(subKey, 20, state[13]);
            WriteU32LE(subKey, 24, state[14]);
            WriteU32LE(subKey, 28, state[15]);

            state.Clear();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b;
            d ^= a;
            d = BitOperations.RotateLeft(d, 16);
            c += d;
            b ^= c;
            b = BitOperations.RotateLeft(b, 12);
            a += b;
            d ^= a;
            d = BitOperations.RotateLeft(d, 8);
            c += d;
            b ^= c;
            b = BitOperations.RotateLeft(b, 7);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void WriteU32LE(Span<byte> buffer, int offset, uint value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(offset, 4), value);
        }
    }
}