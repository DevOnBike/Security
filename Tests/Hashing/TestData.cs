using System.Text;

namespace DevOnBike.Security.Tests.Hashing;

public static class TestData
{
    public const string SourceText = "The quick brown fox jumps over the lazy dog";
    public static readonly byte[] SourceBytes = Encoding.UTF8.GetBytes(SourceText);
}