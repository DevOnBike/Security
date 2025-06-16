using System.Security.Cryptography;
using DevOnBike.Heimdall.Hashing;
using DevOnBike.Heimdall.Randomization;
using Microsoft.Extensions.Options;

namespace DevOnBike.Security.Tests.Hashing
{
    public sealed class Pbkdf2PasswordHasherTests
    {
        private const string TestPassword = "MySecurePassword_123!";               

        [Fact]
        public void HashPassword_Then_VerifyPassword_Should_Succeed()
        {
            // Arrange
            var hasher = CreateHasher();

            // Act
            var hashedPassword = hasher.Hash(TestPassword);
            var isPasswordCorrect = hasher.Verify(TestPassword, hashedPassword);

            // Assert
            Assert.True(isPasswordCorrect);
            Assert.NotNull(hashedPassword);
            Assert.NotEmpty(hashedPassword);
        }

        
        [Fact]
        public void VerifyPassword_With_IncorrectPassword_Should_Fail()
        {
            // Arrange
            var hasher = CreateHasher();
            var hashedPassword = hasher.Hash(TestPassword);

            // Act
            var isPasswordCorrect = hasher.Verify(hashedPassword, "ThisIsTheWrongPassword");

            // Assert
            Assert.False(isPasswordCorrect);
        }

        [Theory]
        [InlineData("not;enough;parts")]
        [InlineData("not_an_int;c2FsdA==;aGFzaA==")] // Invalid iteration count
        [InlineData("1000;invalid-base64;aGFzaA==")] // Invalid salt
        [InlineData("1000;c2FsdA==;invalid-base64")] // Invalid hash
        [InlineData(null)]
        [InlineData("")]
        [InlineData(";;")]
        public void VerifyPassword_With_InvalidHashFormat_Should_Fail(string invalidHash)
        {
            // Arrange
            var hasher = CreateHasher();

            // Act
            var result = hasher.Verify(invalidHash, TestPassword);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void HashedPassword_Should_BeDifferent_ForSamePassword_DueToRandomSalt()
        {
            // Arrange
            var hasher = CreateHasher();

            // Act
            var hash1 = hasher.Hash(TestPassword);
            var hash2 = hasher.Hash(TestPassword);

            // Assert
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void VerifyPassword_Should_Succeed_EvenIfHasherHasDifferentDefaultIterations()
        {
            // Arrange
            // Create a hash using a low iteration count (e.g., old password)
            var oldHasher = CreateHasher(1000); // Old hasher with 1000 iterations
            var oldHashedPassword = oldHasher.Hash(TestPassword);

            // Now, simulate the application being updated to use a higher iteration count
            var newHasher = CreateHasher(5000);

            // Act
            // The new hasher should still be able to verify the old password because
            // the iteration count is stored inside the hash string itself.
            var isPasswordCorrect = newHasher.Verify(TestPassword, oldHashedPassword);

            // Assert
            Assert.True(isPasswordCorrect);
        }

        private IOptions<PasswordHasherOptions> CreateOptions(int iterationCount = 1000) // Use low iteration for fast tests
        {
            var options = new PasswordHasherOptions { Iterations = iterationCount };

            return Options.Create(options);
        }

        private Pbkdf2PasswordHasher CreateHasher(int iterationCount = 1000)
        {
            return new Pbkdf2PasswordHasher(CreateOptions(iterationCount), HashAlgorithmName.SHA256, new DefaultRandom());
        }
    }
}
