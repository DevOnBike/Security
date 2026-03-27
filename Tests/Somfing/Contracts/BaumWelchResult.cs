namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    /// <summary>
    /// Wynik pojedynczego treningu Baum-Welch.
    /// </summary>
    public sealed class BaumWelchResult
    {
        /// <summary>Historia log-likelihood po każdej iteracji.</summary>
        public IReadOnlyList<double> LogLikelihoodHistory { get; init; } = [];

        /// <summary>Liczba wykonanych iteracji.</summary>
        public int Iterations => LogLikelihoodHistory.Count;

        /// <summary>Czy algorytm zbiegł przed wyczerpaniem MaxIterations.</summary>
        public bool Converged { get; init; }

        /// <summary>Końcowe log-likelihood (ostatnia iteracja).</summary>
        public double FinalLogLikelihood => LogLikelihoodHistory.Count > 0 ? LogLikelihoodHistory[^1] : double.NegativeInfinity;

        public override string ToString() => $"Converged={Converged}  Iterations={Iterations} FinalLogLikelihood={FinalLogLikelihood:F4}";
    }
}