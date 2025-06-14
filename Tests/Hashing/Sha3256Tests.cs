using System.Text;
using DevOnBike.Heimdall.Hashing;

namespace DevOnBike.Security.Tests.Hashing
{
    public sealed class Sha3256Tests
    {
        [Fact]
        public void HashSizeInBytes_ShouldReturn32()
        {
            // Arrange
            var sut = Sha3256.Instance;
            const int expectedSize = 32;

            // Act
            var actualSize = sut.HashSizeInBytes;

            // Assert
            Assert.Equal(expectedSize, actualSize);
        }

        [Fact]
        public void Hash_ShouldProduceCorrectAndDeterministicHash()
        {
            // Arrange
            var sut = Sha3256.Instance;
            // Known SHA3-256 hash for the test string "The quick brown fox jumps over the lazy dog"
            var expectedHash =
                Convert.FromHexString("619AB2678318DD168564E35A885D5A5C9B279C4189392DD142F9A7F66A4076C2");

            // Act
            var firstHash = sut.Hash(TestData.SourceBytes);
            var secondHash = sut.Hash(TestData.SourceBytes);

            // Assert
            Assert.NotNull(firstHash);
            Assert.Equal(sut.HashSizeInBytes, firstHash.Length);

            // 1. Verify that hashing the same data twice produces the same result (it's deterministic).
            Assert.Equal(firstHash, secondHash);

            // 2. Verify that the hash matches the known correct hash for the input.
            Assert.Equal(expectedHash, firstHash);
        }

        [Fact]
        public void Hash_ShouldProduceDifferentHashes_ForDifferentInputs()
        {
            // Arrange
            var sut = Sha3256.Instance;
            var sourceBytes1 = Encoding.UTF8.GetBytes("First input");
            var sourceBytes2 = Encoding.UTF8.GetBytes("Second input which is different");

            // Act
            var hash1 = sut.Hash(sourceBytes1);
            var hash2 = sut.Hash(sourceBytes2);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void Hash_ShouldProduceCorrectHash_ForEmptyInput()
        {
            // Arrange
            var sut = Sha3256.Instance;
            // Known SHA3-256 hash for an empty input
            var expectedHash =
                Convert.FromHexString("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A");

            // Act
            var actualHash = sut.Hash([]);

            // Assert
            Assert.Equal(expectedHash, actualHash);
        }
        
        [Fact]
        public async Task HashAsync_ShouldProduceCorrectHash()
        {
            // Arrange
            // Assuming Sha3256 implements IHashAsync
            var sut = Sha3256.Instance;
            var expectedHash = Convert.FromHexString(KnownHashForTestString);
            await using var stream = new MemoryStream(TestData.SourceBytes);
            
            // Act
            // We cast to IHashAsync to specifically test the interface contract.
            var actualHash = await sut.HashAsync(stream, CancellationToken.None);

            // Assert
            Assert.Equal(expectedHash, actualHash);
        }
        
        [Fact]
        public async Task SyncAndAsyncHashes_ShouldBeIdentical_ForSameData()
        {
            // Arrange
            // Assuming Sha3256 implements both IHash and IHashAsync interfaces
            var sut = new Sha3256();
            await using var stream = new MemoryStream(TestData.SourceBytes);

            // Act
            var syncHash = sut.Hash(TestData.SourceBytes);
            var asyncHash = await sut.HashAsync(stream, CancellationToken.None);

            // Assert
            Assert.Equal(syncHash, asyncHash);
        }
        
        // Known-good hash values for consistent test inputs.
        private const string KnownHashForTestString = "619AB2678318DD168564E35A885D5A5C9B279C4189392DD142F9A7F66A4076C2";
        private const string KnownHashForEmptyInput = "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A";

    }
}