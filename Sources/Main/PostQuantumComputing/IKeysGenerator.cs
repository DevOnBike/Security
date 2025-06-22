using DevOnBike.Heimdall.PostQuantumComputing.Contracts;

namespace DevOnBike.Heimdall.PostQuantumComputing
{
    public interface IKeysGenerator
    {
        PqcKeyPair GenerateKeyPair();
    }
}

