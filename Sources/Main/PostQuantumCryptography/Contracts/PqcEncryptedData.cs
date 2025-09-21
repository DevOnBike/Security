namespace DevOnBike.Heimdall.PostQuantumCryptography.Contracts
{
    public class PqcEncryptedData
    {
        /// <summary>
        /// The encapsulation blob from the Post-Quantum Cryptography (PQC) algorithm (e.g., Kyber).
        /// This is used to regenerate the Key Encryption Key (KEK) during decryption.
        /// </summary>
        public byte[] Encapsulation { get; set; }

        /// <summary>
        /// The Data Encryption Key (DEK), which was used to encrypt the actual data, wrapped by the KEK.
        /// This is a critical component of envelope encryption.
        /// </summary>
        public byte[] WrappedDek { get; set; }

        /// <summary>
        /// The nonce (or Initialization Vector) used for the AES-GCM encryption of the DEK.
        /// </summary>
        public byte[] KekNonce { get; set; }

        /// <summary>
        /// The authentication tag for the DEK's encryption. Used to verify its integrity.
        /// </summary>
        public byte[] KekTag { get; set; }

        /// <summary>
        /// The nonce (or Initialization Vector) used for the AES-GCM encryption of the main data.
        /// </summary>
        public byte[] DataNonce { get; set; }

        /// <summary>
        /// The authentication tag for the main data's encryption. Used to verify its integrity.
        /// </summary>
        public byte[] DataTag { get; set; }

        /// <summary>
        /// The actual encrypted payload (the ciphertext).
        /// </summary>
        public byte[] EncryptedData { get; set; }
    }

}
