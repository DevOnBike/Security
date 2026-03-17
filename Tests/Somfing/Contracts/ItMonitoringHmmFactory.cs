namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    /// <summary>
    /// Fabryka tworząca gotowy, wstępnie skonfigurowany model do testów.
    /// Zakładamy 2-wymiarowy wektor obserwacji: [Użycie CPU (0.0 - 1.0), Użycie RAM (0.0 - 1.0)]
    /// </summary>
    public static class ItMonitoringHmmFactory
    {
        public static ContinuousHMM CreateCpuAndRamModel()
        {
            // --- Krok 4: Prawdopodobieństwa Startowe i Przejść ---
            
            // Prawdopodobieństwo, w jakim stanie znajduje się serwer w momencie uruchomienia monitoringu.
            var startProbs = new Dictionary<ServerState, double>
            {
                { ServerState.Healthy, 0.90 }, // Najpewniej startujemy jako zdrowi
                { ServerState.Degraded, 0.09 },
                { ServerState.Critical, 0.01 }
            };

            // Macierz przejść: Prawdopodobieństwo przejścia ze stanu A do stanu B w kolejnej sekundzie.
            var transProbs = new Dictionary<ServerState, Dictionary<ServerState, double>>
            {
                { ServerState.Healthy, new Dictionary<ServerState, double> { 
                    { ServerState.Healthy, 0.95 },  // Zdrowy lubi pozostawać zdrowy
                    { ServerState.Degraded, 0.04 }, // Czasem zaczyna się dławić
                    { ServerState.Critical, 0.01 }  // Rzadko pada nagle (chyba że kernel panic)
                }},
                { ServerState.Degraded, new Dictionary<ServerState, double> { 
                    { ServerState.Healthy, 0.10 },  // Skok obciążenia minął
                    { ServerState.Degraded, 0.80 }, // Utrzymuje się w stanie dławienia
                    { ServerState.Critical, 0.10 }  // Stan pogarsza się do awarii
                }},
                { ServerState.Critical, new Dictionary<ServerState, double> { 
                    { ServerState.Healthy, 0.05 },  // Ktoś ubił proces / zrestartował
                    { ServerState.Degraded, 0.15 }, 
                    { ServerState.Critical, 0.80 }  // Awaria trwa, dopóki ktoś nie zainterweniuje
                }}
            };

            // --- Krok 5: Modele Emisji (Nasze wielowymiarowe Gaussy) ---
            
            var emissionModels = new Dictionary<ServerState, IEmissionModel>();

            // 1. HEALTHY: CPU średnio 20% (0.2), RAM 40% (0.4)
            double[] healthyMean = { 0.20, 0.40 };
            double[,] healthyCov = { 
                { 0.02, 0.00 }, // Wariancja CPU (niskie rozrzuty)
                { 0.00, 0.02 }  // Wariancja RAM
            };
            emissionModels[ServerState.Healthy] = new CholeskyMultivariateGaussian(healthyMean, healthyCov);

            // 2. DEGRADED: CPU średnio 75% (0.75), RAM 80% (0.80)
            double[] degradedMean = { 0.75, 0.80 };
            double[,] degradedCov = { 
                { 0.05, 0.02 }, // Wyższa wariancja (obciążenie mocniej skacze) + lekka korelacja dodatnia CPU i RAM
                { 0.02, 0.05 }  
            };
            emissionModels[ServerState.Degraded] = new CholeskyMultivariateGaussian(degradedMean, degradedCov);

            // 3. CRITICAL: CPU wbite na 99% (0.99), RAM na 95% (0.95)
            // Bardzo mała wariancja, bo serwer po prostu "leży" na maksymalnych obrotach i nic się nie zmienia.
            double[] criticalMean = { 0.99, 0.95 };
            double[,] criticalCov = { 
                { 0.001, 0.00 }, 
                { 0.00, 0.005 } 
            };
            emissionModels[ServerState.Critical] = new CholeskyMultivariateGaussian(criticalMean, criticalCov);

            return new ContinuousHMM(startProbs, transProbs, emissionModels);
        }
    }
}