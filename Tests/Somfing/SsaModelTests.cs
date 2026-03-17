using DevOnBike.Security.Tests.Somfing.Contracts;
using Microsoft.ML;
using Microsoft.ML.Transforms.TimeSeries;

namespace DevOnBike.Security.Tests.Somfing
{
    public class SsaModelTests
    {
        [Fact]
        public void SsaForecasting_ShouldPredictCorrectHorizonLength_AndValidValues()
        {
            // ==========================================
            // ARRANGE: Przygotowanie środowiska i danych
            // ==========================================

            // Używamy "seed" (ziarna), aby test był deterministyczny 
            // - zawsze da te same wyniki przy tym samym kodzie
            var mlContext = new MLContext(seed: 42);
            var random = new Random(42);

            var historicalData = new List<CpuData>();
            for (int i = 0; i < 30; i++)
            {
                historicalData.Add(new CpuData
                {
                    Timestamp = DateTime.Now.AddDays(-30 + i),
                    CpuUsage = 50.0f + (i * 0.5f) + (float)random.NextDouble() * 5.0f
                });
            }

            IDataView dataView = mlContext.Data.LoadFromEnumerable(historicalData);
            int expectedHorizon = 3;

            // Definicja pipeline'u (parametry zoptymalizowane pod 30 próbek)
            var forecastingPipeline = mlContext.Forecasting.ForecastBySsa(
                outputColumnName: nameof(CpuForecast.ForecastedCpuUsage),
                inputColumnName: nameof(CpuData.CpuUsage),
                windowSize: 7,
                seriesLength: 14,
                trainSize: 30,
                horizon: expectedHorizon);

            // ==========================================
            // ACT: Trenowanie i przewidywanie
            // ==========================================
            var model = forecastingPipeline.Fit(dataView);
            var forecastingEngine = model.CreateTimeSeriesEngine<CpuData, CpuForecast>(mlContext);
            var forecast = forecastingEngine.Predict();

            // ==========================================
            // ASSERT: Sprawdzanie poprawności wyników
            // ==========================================

            // 1. Sprawdzamy, czy model w ogóle coś zwrócił
            Assert.NotNull(forecast);
            Assert.NotNull(forecast.ForecastedCpuUsage);

            // 2. Sprawdzamy, czy zwrócił dokładnie tyle kroków, o ile prosiliśmy (Horizon)
            Assert.Equal(expectedHorizon, forecast.ForecastedCpuUsage.Length);

            // 3. Weryfikacja jakości liczb (tzw. Sanity Check)
            Assert.All(forecast.ForecastedCpuUsage, predictedValue =>
            {
                // Wynik nie może być NaN (Not a Number) ani Infinity
                Assert.False(float.IsNaN(predictedValue));
                Assert.False(float.IsInfinity(predictedValue));

                // Z biznesowego punktu widzenia, użycie CPU nie może być mniejsze niż 0
                Assert.True(predictedValue > 0f, $"Przewidziane użycie CPU ({predictedValue}) nie powinno być ujemne.");
            });
        }

        [Fact]
        public void SsaModel_ShouldSaveAndLoadCorrectly_AndProduceIdenticalForecasts()
        {
            // ==========================================
            // ARRANGE: Przygotowanie środowiska i danych
            // ==========================================
            var mlContext = new MLContext(seed: 42);
            var random = new Random(42);

            var historicalData = new List<CpuData>();
            for (int i = 0; i < 30; i++)
            {
                historicalData.Add(new CpuData
                {
                    Timestamp = DateTime.Now.AddDays(-30 + i),
                    CpuUsage = 50.0f + (i * 0.5f) + (float)random.NextDouble() * 5.0f
                });
            }

            IDataView dataView = mlContext.Data.LoadFromEnumerable(historicalData);

            // Definiujemy i trenujemy oryginalny model
            var forecastingPipeline = mlContext.Forecasting.ForecastBySsa(
                outputColumnName: nameof(CpuForecast.ForecastedCpuUsage),
                inputColumnName: nameof(CpuData.CpuUsage),
                windowSize: 7,
                seriesLength: 14,
                trainSize: 30,
                horizon: 3);

            ITransformer originalModel = forecastingPipeline.Fit(dataView);

            // Tworzymy silnik i generujemy prognozę z ORYGINALNEGO modelu
            var originalEngine = originalModel.CreateTimeSeriesEngine<CpuData, CpuForecast>(mlContext);
            var originalForecast = originalEngine.Predict();

            // ==========================================
            // ACT: Symulacja eksportu i importu modelu
            // ==========================================
            ITransformer loadedModel;

            // Używamy strumienia w pamięci zamiast fizycznego pliku .zip
            using (var memoryStream = new MemoryStream())
            {
                // 1. Zapisujemy model i jego schemat danych do strumienia
                mlContext.Model.Save(originalModel, dataView.Schema, memoryStream);

                // Przewijamy strumień na początek, aby móc z niego czytać
                memoryStream.Position = 0;

                // 2. Wczytujemy model ze strumienia (wypakowanie z "zipa")
                loadedModel = mlContext.Model.Load(memoryStream, out DataViewSchema loadedSchema);
            }

            // Tworzymy NOWY silnik z WCZYTANEGO modelu i generujemy prognozę
            var loadedEngine = loadedModel.CreateTimeSeriesEngine<CpuData, CpuForecast>(mlContext);
            var loadedForecast = loadedEngine.Predict();

            // ==========================================
            // ASSERT: Porównanie modelu przed i po
            // ==========================================

            Assert.NotNull(loadedModel);
            Assert.NotNull(loadedForecast.ForecastedCpuUsage);

            // Najważniejszy test: Odtworzony model musi dawać co do ułamka takie same liczby!
            Assert.Equal(originalForecast.ForecastedCpuUsage.Length, loadedForecast.ForecastedCpuUsage.Length);

            for (int i = 0; i < originalForecast.ForecastedCpuUsage.Length; i++)
            {
                Assert.Equal(
                    originalForecast.ForecastedCpuUsage[i],
                    loadedForecast.ForecastedCpuUsage[i],
                    precision: 4); // Tolerancja dla zaokrągleń zmiennoprzecinkowych (float)
            }
        }
    }
}
