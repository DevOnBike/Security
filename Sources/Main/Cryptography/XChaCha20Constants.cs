namespace DevOnBike.Heimdall.Cryptography
{
    /// <summary>
    /// Defines constants for the XChaCha20-Poly1305 algorithm.
    /// </summary>
    public static class XChaCha20Constants
    {
        public const int KeySizeInBytes = 32;   // 256-bit
        public const int NonceSizeInBytes = 24;  // 192-bit
        public const int TagSizeInBytes = 16;    // 128-bit
    }
}
