namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    public class AnomalyPrediction
    {
        // IidChangePointEstimator zwraca wektor 4 wartości:
        // [0] Alert (1 jeśli to anomalia, 0 jeśli nie)
        // [1] Obliczony wynik (Score)
        // [2] P-Value (prawdopodobieństwo, im bliżej 0, tym dziwniejsze zdarzenie)
        // [3] Wartość Martingale (wewnętrzna metryka pewności algorytmu)
        [Microsoft.ML.Data.VectorType(4)]
        public double[] Prediction { get; set; }
    }
}