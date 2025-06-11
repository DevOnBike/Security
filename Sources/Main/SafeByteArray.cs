using System.Security.Cryptography;

namespace DevOnBike.Heimdall
{
    public readonly struct SafeByteArray : IDisposable
    {
        public int Length => _buffer.Length;
        public Span<byte> Span => _buffer;
        public ReadOnlySpan<byte> ReadOnlySpan => _buffer;

        private readonly byte[] _buffer;

        public SafeByteArray(byte[] buffer)
        {
            _buffer = buffer;
        }

        public void Dispose()
        {
            try
            {
                CryptographicOperations.ZeroMemory(_buffer);
            }
            catch
            {
                // CA1065: Do not raise exceptions in unexpected locations
            }
        }

        public static implicit operator byte[](SafeByteArray sb)
        {
            return sb._buffer;
        }
        
        public static implicit operator ReadOnlySpan<byte>(SafeByteArray sb)
        {
            return sb._buffer;
        }

    }
}