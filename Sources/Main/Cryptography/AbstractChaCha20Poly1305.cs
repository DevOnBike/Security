using System.Runtime.CompilerServices;
using static DevOnBike.Heimdall.Cryptography.ChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    public abstract class AbstractChaCha20Poly1305
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected virtual byte[] CreateNonceBuffer()
        {
            return new byte[NonceSizeInBytes];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected virtual byte[] CreateKeyBuffer()
        {
            return new byte[KeySizeInBytes];
        }
    }
}

