namespace DevOnBike.Heimdall.Hashing
{
    public interface IHash
    {
        string Id { get; }
        int HashSize { get; }
        byte[] ComputeHash(byte[] input);
    }
}