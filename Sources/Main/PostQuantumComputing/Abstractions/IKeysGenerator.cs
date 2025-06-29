using DevOnBike.Heimdall.PostQuantumComputing.Contracts;

namespace DevOnBike.Heimdall.PostQuantumComputing.Abstractions
{
    public interface IKeysGenerator
    {
        PqcKeyPair GenerateKeyPair();
    }
}

