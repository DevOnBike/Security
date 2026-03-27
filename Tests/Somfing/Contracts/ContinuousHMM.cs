
// Twój interfejs

namespace DevOnBike.Security.Tests.Somfing.Contracts
{
    // Krok 3: Definiujemy możliwe ukryte stany naszego systemu IT

    /// <summary>
    /// Główna klasa przechowująca kompletną definicję Ukrytego Modelu Markowa (HMM) dla danych ciągłych.
    /// Wszystkie prawdopodobieństwa przejść i początkowe są przechowywane jako logarytmy naturalne!
    /// </summary>
    public class ContinuousHMM
    {
        public IReadOnlyDictionary<ServerState, double> InitialLogProbabilities { get; }
        public IReadOnlyDictionary<ServerState, IReadOnlyDictionary<ServerState, double>> TransitionLogProbabilities { get; }
        public IReadOnlyDictionary<ServerState, IEmissionModel> EmissionModels { get; }

        public ContinuousHMM(
            Dictionary<ServerState, double> initialProbabilities,
            Dictionary<ServerState, Dictionary<ServerState, double>> transitionProbabilities,
            Dictionary<ServerState, IEmissionModel> emissionModels)
        {
            // Walidacja czy mamy te same stany wszędzie
            var states = Enum.GetValues<ServerState>();
            if (states.Any(s => !emissionModels.ContainsKey(s) || !initialProbabilities.ContainsKey(s) || !transitionProbabilities.ContainsKey(s)))
            {
                throw new ArgumentException("Brakuje konfiguracji dla jednego lub więcej stanów serwera.");
            }

            // 1. Konwersja prawdopodobieństw początkowych (Pi) na logarytmy
            var initLogProbs = new Dictionary<ServerState, double>();
            foreach (var kvp in initialProbabilities)
            {
                // Zabezpieczenie przed log(0)
                initLogProbs[kvp.Key] = kvp.Value > 0 ? Math.Log(kvp.Value) : double.NegativeInfinity;
            }
            InitialLogProbabilities = initLogProbs;

            // 2. Konwersja macierzy przejść (A) na logarytmy
            var transLogProbs = new Dictionary<ServerState, IReadOnlyDictionary<ServerState, double>>();
            foreach (var fromState in transitionProbabilities)
            {
                var toStatesLog = new Dictionary<ServerState, double>();
                foreach (var toState in fromState.Value)
                {
                    toStatesLog[toState.Key] = toState.Value > 0 ? Math.Log(toState.Value) : double.NegativeInfinity;
                }
                transLogProbs[fromState.Key] = toStatesLog;
            }
            TransitionLogProbabilities = transLogProbs;

            // 3. Przypisanie gotowych modeli emisji Gaussa (B)
            EmissionModels = emissionModels.ToDictionary(k => k.Key, v => v.Value);
        }
    }

}