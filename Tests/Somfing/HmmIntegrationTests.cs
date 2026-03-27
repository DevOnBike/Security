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
            var monitor = new HmmRealTimeMonitor(decoder, 2, 5);

            // Symulujemy silnik alertów (State Machine) - wymaga 2 klatek pod rząd do zmiany stanu
            var alertEngine = new AlertEngine(requireConsecutiveFrames: 2);
            var activeAlertState = ServerState.Healthy;

            // ==========================================
            // 2. ACT & ASSERT: Faza Normalnej Pracy
            // ==========================================
            for (var i = 0; i < 10; i++)
            {
                var diag = monitor.ProcessNewObservation([0.20, 0.40]);
                activeAlertState = alertEngine.ProcessDiagnosis(diag);
            }
            Assert.Equal(ServerState.Healthy, activeAlertState);

            // ==========================================
            // 3. ACT & ASSERT: Fałszywy Alarm (Pojedynczy Pik)
            // ==========================================
            // HMM zareaguje na ten pik "paniką" (zwróci Critical), ale nasz silnik alertów 
            // zażąda potwierdzenia w kolejnej sekundzie.
            var spikeDiag = monitor.ProcessNewObservation([0.99, 0.95]);
            activeAlertState = alertEngine.ProcessDiagnosis(spikeDiag);

            // System nadal widnieje jako Healthy w systemie alertowym!
            Assert.Equal(ServerState.Healthy, activeAlertState);

            // Kolejna klatka powraca do normy. Viterbi uspokaja się i zwraca Healthy.
            var recoveryDiag = monitor.ProcessNewObservation([0.20, 0.40]);
            activeAlertState = alertEngine.ProcessDiagnosis(recoveryDiag);

            // Utrzymaliśmy status Healthy. PagerDuty milczy!
            Assert.Equal(ServerState.Healthy, activeAlertState);

            // ==========================================
            // 4. ACT & ASSERT: Prawdziwa Awaria (Trwałe Obciążenie)
            // ==========================================
            // Teraz system zaczyna się dławić i stanutrzymuje się.
            for (var i = 0; i < 5; i++)
            {
                var failureDiag = monitor.ProcessNewObservation([0.99, 0.95]);
                activeAlertState = alertEngine.ProcessDiagnosis(failureDiag);
            }

            // HMM zwraca Critical kilka razy z rzędu. Silnik alertów ma potwierdzenie i zmienia stan.
            Assert.Equal(ServerState.Critical, activeAlertState);
        }

        // --- Klasa pomocnicza reprezentująca logikę biznesową ponad HMM ---
        private class AlertEngine
        {
            private readonly int _requiredFrames;
            private int _consecutiveCount = 0;
            private ServerState _currentAlertState = ServerState.Healthy;
            private ServerState _lastDiagnosis = ServerState.Healthy;

            public AlertEngine(int requireConsecutiveFrames)
            {
                _requiredFrames = requireConsecutiveFrames;
            }

            public ServerState ProcessDiagnosis(ServerState hmmDiagnosis)
            {
                if (hmmDiagnosis == _lastDiagnosis)
                {
                    _consecutiveCount++;
                }
                else
                {
                    _consecutiveCount = 1;
                    _lastDiagnosis = hmmDiagnosis;
                }

                if (_consecutiveCount >= _requiredFrames)
                {
                    _currentAlertState = hmmDiagnosis;
                }

                return _currentAlertState;
            }
        }
    }
}