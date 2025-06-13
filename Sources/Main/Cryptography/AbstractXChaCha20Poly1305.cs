using System.Runtime.CompilerServices;
using static DevOnBike.Heimdall.Cryptography.XChaCha20Constants;

namespace DevOnBike.Heimdall.Cryptography
{
    public abstract class AbstractXChaCha20Poly1305
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

