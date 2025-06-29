namespace DevOnBike.Heimdall.Cryptography.Abstractions
{
    public interface IFormatPreservingEncryption
    {
        string Encrypt(string text);

        string Decrypt(string encrypted);
    }
}

