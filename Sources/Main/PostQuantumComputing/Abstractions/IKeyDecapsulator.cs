namespace DevOnBike.Heimdall.PostQuantumComputing.Abstractions
{
    /// <summary>
    /// Defines the functionality for a Key Encapsulation Mechanism (KEM) receiver.
    /// </summary>
    public interface IKeyDecapsulator
    {
        /// <summary>
        /// Recovers the shared secret from the encapsulated data using the private key.
        /// </summary>
        /// <param name="encapsulation">The encapsulated secret received from the sender.</param>
        /// <returns>The derived shared secret.</returns>
        byte[] Decapsulate(byte[] encapsulation);
    }
}