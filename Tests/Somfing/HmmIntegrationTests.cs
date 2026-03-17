using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    public class HmmIntegrationTests
    {
        [Fact]
        public void RealTimeMonitor_Scenario_IgnoresSingleSpike_ButCatchesSustainedFailure()
        {
            // ==========================================
            // 1. ARRANGE (Konfiguracja środowiska)
            // ==========================================
            var hmmModel = ItMonitoringHmmFactory.CreateCpuAndRamModel();
            var decoder = new ViterbiDecoder(hmmModel);
            
            // Używamy małego okna czasowego (np. 5 klatek/sekund), 
            // aby test był szybki i przewidywalny.
            var monitor = new HmmRealTimeMonitor(decoder, 2, 5);

            var currentState = ServerState.Healthy;

            // ==========================================
            // 2. ACT & ASSERT: Faza Normalnej Pracy
            // ==========================================
            // Pompujemy 10 klatek ze standardowym użyciem (CPU ~20%, RAM ~40%)
            for (var i = 0; i < 10; i++)
            {
                currentState = monitor.ProcessNewObservation([0.20, 0.40]);
            }
            
            // System musi być zdrowy po 10 sekundach dobrej pracy
            Assert.Equal(ServerState.Healthy, currentState);

            // ==========================================
            // 3. ACT & ASSERT: Fałszywy Alarm (Pojedynczy Pik)
            // ==========================================
            // Nagle w jednej klatce CPU skacze do 99%, a RAM do 95%
            currentState = monitor.ProcessNewObservation([0.99, 0.95]);

            // KLUCZOWY MOMENT HMM:
            // Koszt zmiany stanu w macierzy przejść jest wyższy niż kara za zignorowanie jednej chorej metryki.
            // Zwykły system wysłałby alert. Nasz model ma to zignorować!
            Assert.Equal(ServerState.Healthy, currentState);

            // Kolejna klatka wraca do normy
            currentState = monitor.ProcessNewObservation([0.20, 0.40]);
            Assert.Equal(ServerState.Healthy, currentState);

            // ==========================================
            // 4. ACT & ASSERT: Prawdziwa Awaria (Trwałe Obciążenie)
            // ==========================================
            // Teraz system faktycznie zaczyna się dławić i to utrzymuje.
            // Wysyłamy metryki awarii przez tyle klatek, ile wynosi nasze okno przesuwne.
            for (var i = 0; i < 5; i++)
            {
                currentState = monitor.ProcessNewObservation([0.99, 0.95]);
            }

            // Teraz okno zapełniło się anomalią. Prawdopodobieństwo tkwienia w stanie Healthy 
            // przy takich metrykach stało się zerowe. Viterbi "łamie się" i zmienia ścieżkę.
            // System MUSI wyzwolić stan krytyczny.
            Assert.Equal(ServerState.Critical, currentState);
        }
    }
}