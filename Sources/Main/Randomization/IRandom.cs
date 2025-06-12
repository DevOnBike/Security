namespace DevOnBike.Heimdall.Randomization
{
    public interface IRandom
    {
        int Next();
        void Fill(byte[] toFill);
        void Fill(Span<byte> toFill);
        byte[] GenerateSeed(int numBytes);
    }
}