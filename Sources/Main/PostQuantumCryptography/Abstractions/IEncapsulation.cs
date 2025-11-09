namespace DevOnBike.Heimdall.PostQuantumCryptography.Abstractions
{
    /// <summary>
    /// Defines the contract for a Post-Quantum Key Encapsulation Mechanism (KEM).
    /// A KEM is used to establish a secure shared secret between two parties.
    /// </summary>
    public interface IEncapsulation : IKeyEncapsulator, IKeyDecapsulator
    {
        
    }
}

