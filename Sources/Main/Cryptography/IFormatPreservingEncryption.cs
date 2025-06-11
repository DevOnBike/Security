namespace DevOnBike.Heimdall.Cryptography
{
    public interface IFormatPreservingEncryption
    {
        string Encrypt(string text);

        string Decrypt(string encrypted);
    }
}

