namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    public interface IEmissionModel
    {
        /// <summary>
        /// Wymiar wektora obserwacji d.
        /// Każde wywołanie <see cref="GetLogProbability"/> musi dostarczyć
        /// wektor dokładnie tej długości.
        /// </summary>
        int Dimension { get; }
 
        /// <summary>
        /// Logarytm naturalny gęstości prawdopodobieństwa obserwacji:
        ///
        ///   ln p(observation | ten model emisji)
        ///
        /// Kontrakt:
        ///   • Zwraca wartość ≤ 0 dla rozkładów ciągłych z normalizacją = 1
        ///     (możliwe wartości > 0 gdy gęstość lokalna > 1, co jest poprawne
        ///      dla wąskich rozkładów — nie jest to prawdopodobieństwo lecz gęstość).
        ///   • Nigdy nie zwraca NaN ani +Infinity.
        ///   • Zwraca double.NegativeInfinity gdy obserwacja ma zerową gęstość.
        ///   • Rzuca <see cref="ArgumentException"/> gdy observation.Length != Dimension.
        /// </summary>
        double GetLogProbability(double[] observation);
    }
}