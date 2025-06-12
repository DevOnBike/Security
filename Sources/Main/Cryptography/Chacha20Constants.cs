namespace DevOnBike.Heimdall.Cryptography
{
    public static class ChaCha20Constants
    {
        public const int KeySizeInBytes = 256 / 8;
        public const int NonceSizeInBytes = 96 / 8;
        public const int TagSizeInBytes = 128 / 8;
    }
}

