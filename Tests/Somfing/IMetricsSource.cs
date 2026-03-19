namespace DevOnBike.Security.Tests.Somfing
{
    /// <summary>
    /// Kontrakt źródła metryk. Implementuje go zarówno MetricsSimulator (testy)
    /// jak i prawdziwy adapter Prometheus/OTel (produkcja).
    /// </summary>
    public interface IMetricsSource : IAsyncDisposable
    {
        /// <summary>
        /// Oczekuje na następną próbkę i ją zwraca.
        /// Blokuje (asynchronicznie) do momentu gdy próbka będzie gotowa.
        /// Rzuca OperationCanceledException gdy cancellationToken jest anulowany.
        /// </summary>
        ValueTask<double[]> ReadNextAsync(CancellationToken cancellationToken = default);

        /// <summary>Wymiar wektora obserwacji d.</summary>
        int Dimension { get; }

        /// <summary>Czy źródło ma więcej próbek (false = koniec sekwencji).</summary>
        bool HasMore { get; }
    }
}