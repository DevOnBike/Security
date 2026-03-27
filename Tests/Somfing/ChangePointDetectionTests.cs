using DevOnBike.Security.Tests.Somfing.Contracts;
using Microsoft.ML;

namespace DevOnBike.Security.Tests.Somfing
{
    public class ChangePointDetectionTests
    {
        [Fact]
        public void DetectIidChangePoint_ShouldFlagPermanentShiftInCpuUsage()
        {
            // ==========================================
            // ARRANGE: Generowanie danych symulujących awarię
            // ==========================================
            var mlContext = new MLContext(seed: 42);
            var random = new Random(42);
            var metrics = new List<ClusterMetric>();

            // Faza 1: Normalne, stabilne działanie (CPU ~30%) przez 30 pomiarów
            for (var i = 0; i < 30; i++)
            {
                metrics.Add(new ClusterMetric
                {
                    Timestamp = DateTime.Now.AddMinutes(i),
                    CpuUsage = 30.0f + (float)random.NextDouble() * 5.0f // Wahnięcia od 30% do 35%
                });
            }

            // Faza 2: Wdrażamy nową wersję z wyciekiem/błędem. CPU skacze i zostaje na ~80%
            var timeOfDeploymentIndex = metrics.Count;
            for (var i = 0; i < 15; i++)
            {
                metrics.Add(new ClusterMetric
                {
                    Timestamp = DateTime.Now.AddMinutes(timeOfDeploymentIndex + i),
                    CpuUsage = 80.0f + (float)random.NextDouble() * 5.0f // Wahnięcia od 80% do 85%
                });
            }

            var dataView = mlContext.Data.LoadFromEnumerable(metrics);

            // ==========================================
            // ACT: Budowa i uruchomienie modelu detekcji
            // ==========================================

            var pipeline = mlContext.Transforms.DetectIidChangePoint(
                outputColumnName: nameof(AnomalyPrediction.Prediction),
                inputColumnName: nameof(ClusterMetric.CpuUsage),
                confidence: 95.0,        // Poziom pewności (95% to standard rynkowy)
                changeHistoryLength: 10  // Jak długie "okno pamięci" algorytm ma analizować (rozmiar bufora)
            );

            // Trenujemy i od razu transformujemy nasze dane
            ITransformer model = pipeline.Fit(dataView);
            var transformedData = model.Transform(dataView);

            // Wyciągamy wyniki z powrotem do łatwej w obsłudze listy C#
            var predictions = mlContext.Data
                .CreateEnumerable<AnomalyPrediction>(transformedData, reuseRowObject: false)
                .ToList();

            // ==========================================
            // ASSERT: Weryfikacja działania algorytmu
            // ==========================================

            Assert.Equal(metrics.Count, predictions.Count);

            // 1. Sprawdzamy, czy w fazie stabilnej (przed wdrożeniem) nie było fałszywych alarmów
            for (var i = 0; i < timeOfDeploymentIndex; i++)
            {
                var isAnomaly = predictions[i].Prediction[0] == 1;
                Assert.False(isAnomaly, $"Fałszywy alarm wykryty w minucie {i}, a system działał stabilnie!");
            }

            // 2. Szukamy, czy algorytm zauważył drastyczną zmianę (Change Point)
            // Zmiana powinna zostać wykryta w momencie wdrożenia lub zaraz po nim
            var changePointDetected = false;
            var detectedAtIndex = -1;

            // Sprawdzamy tylko fazę awarii
            for (var i = timeOfDeploymentIndex; i < predictions.Count; i++)
            {
                if (predictions[i].Prediction[0] == 1) // Jeśli Alert == 1
                {
                    changePointDetected = true;
                    detectedAtIndex = i;
                    break; // Znalazł punkt zmiany, wychodzimy z pętli
                }
            }

            Assert.True(changePointDetected, "Model NIE wykrył drastycznej zmiany zużycia CPU po wdrożeniu!");

            // Opcjonalnie: Logujemy w teście, w której dokładnie minucie padł alarm
            Console.WriteLine($"Wdrożenie było w indeksie: {timeOfDeploymentIndex}");
            Console.WriteLine($"Algorytm podniósł alarm w indeksie: {detectedAtIndex}");
        }
    }
}