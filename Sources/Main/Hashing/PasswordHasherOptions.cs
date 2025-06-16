namespace DevOnBike.Heimdall.Hashing
{
    public class PasswordHasherOptions
    {
        public int Iterations { get; set; } = 10_000;
        public int SaltSize { get; set; } = 32; // 32 bytes = 256 bits
        public int HashSize { get; set; } = 32; // 32 bytes = 256 bits
        
        /// <summary>
        /// The delimiter used to separate parts of the stored hash string.
        /// </summary>
        public char Delimiter { get; set; } = ';';
        
        public static readonly PasswordHasherOptions Default = new();
    }    
}

