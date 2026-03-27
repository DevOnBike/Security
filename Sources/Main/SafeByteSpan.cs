using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace DevOnBike.Heimdall
{
    public readonly ref struct SafeByteSpan : IDisposable
    {
        public Span<byte> Buffer { get; }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public SafeByteSpan(Span<byte> buffer)
        {
            Buffer = buffer;
        }

        public static implicit operator Span<byte>(SafeByteSpan safe) => safe.Buffer;
        public static implicit operator ReadOnlySpan<byte>(SafeByteSpan safe) => safe.Buffer;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Dispose()
        {
            try
            {
                CryptographicOperations.ZeroMemory(Buffer);
            }
            catch
            {
                // no-op
            }
        }
    }
}