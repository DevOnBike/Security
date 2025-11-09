namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    public interface IAsymmetricCryptoService
    {
        int RecommendedKeySizeBits { get; }

        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] encrypted);
    }
}