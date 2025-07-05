using System.Runtime.CompilerServices;

// ReSharper disable once CheckNamespace
namespace Microsoft.AspNetCore.DataProtection
// ReSharper restore CheckNamespace
{
    public static class SecretExtensions
    {
        public static bool IsNullOrEmpty(this ISecret secret)
        {
            return secret?.Length < 1;
        }

        /// <summary>
        /// Unsafe secret as bytes conversion
        /// </summary>
        /// <param name="secret"></param>
        /// <returns></returns>
        public static byte[] GetBytes(this ISecret secret)
        {
            var secretBytes = new byte[secret.Length];
            
            secret.WriteSecretIntoBuffer(new ArraySegment<byte>(secretBytes));

            return secretBytes;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Fill(this ISecret secret, byte[] bytes)
        {
            secret.WriteSecretIntoBuffer(new ArraySegment<byte>(bytes));
        }
    }
}
