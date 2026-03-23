namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    /// <summary>
    /// Wynik treningu Baum-Welch — informacje o zbieżności (iteracje, logP, zbieżność).
    /// </summary>
    public sealed class BaumWelchLearnerResult
    {
        public bool Converged { get; init; }
        public int Iterations { get; init; }
        public double FinalLogLikelihood { get; init; }

        public override string ToString() => $"Converged={Converged}  Iterations={Iterations}  LogLikelihood={FinalLogLikelihood:F4}";
    }
}