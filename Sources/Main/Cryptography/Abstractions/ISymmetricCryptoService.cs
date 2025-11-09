namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    public interface ISymmetricCryptoService
    {
        int RecommendedKeySizeBits { get; }

        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] encrypted);
    }

}