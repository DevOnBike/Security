using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    public class ViterbiDecoder
    {
        private readonly ContinuousHMM _model;
        private readonly ServerState[] _states;

        public ViterbiDecoder(ContinuousHMM model)
        {
            _model = model ?? throw new ArgumentNullException(nameof(model));
            _states = Enum.GetValues<ServerState>();
        }

        /// <summary>
        /// Odkodowuje najbardziej prawdopodobną ścieżkę ukrytych stanów na podstawie ciągu obserwacji.
        /// </summary>
        /// <param name="observations">Lista wektorów metryk (np. [CPU, RAM] dla każdej sekundy)</param>
        /// <returns>Lista stanów serwera odpowiadająca każdej sekundzie z obserwacji</returns>
        public List<ServerState> Decode(IReadOnlyList<double[]> observations)
        {
            return Decode(observations, out _);
        }

        /// <summary>
        /// Odkodowuje najbardziej prawdopodobną ścieżkę ukrytych stanów na podstawie ciągu obserwacji.
        /// </summary>
        /// <param name="observations">Lista wektorów metryk (np. [CPU, RAM] dla każdej sekundy)</param>
        /// <param name="bestPathLogProbability">
        ///   Log-prawdopodobieństwo najlepszej ścieżki: Σₜ [ln A(qₜ₋₁→qₜ) + ln B(qₜ, oₜ)].
        ///   Wartość double.NegativeInfinity oznacza, że żadna ścieżka nie była możliwa
        ///   (obserwacja poza zasięgiem wszystkich emisji) — wynik dekodera jest wtedy
        ///   niezaufany i powinien być traktowany jako brak diagnozy.
        /// </param>
        /// <returns>Lista stanów serwera odpowiadająca każdej sekundzie z obserwacji</returns>
        public List<ServerState> Decode(IReadOnlyList<double[]> observations, out double bestPathLogProbability)
        {
            if (observations == null || observations.Count == 0)
            {
                bestPathLogProbability = double.NegativeInfinity;
                return [];
            }

            var T = observations.Count;

            // viterbi[t][state] przechowuje najwyższe znane log-prawdopodobieństwo dojścia do stanu 'state' w czasie 't'
            var viterbi = new Dictionary<ServerState, double>[T];
            
            // backpointer[t][state] pamięta, z jakiego poprzedniego stanu (w czasie t-1) najlepiej było tu przyjść
            var backpointer = new Dictionary<ServerState, ServerState>[T];

            for (var t = 0; t < T; t++)
            {
                viterbi[t] = new Dictionary<ServerState, double>();
                backpointer[t] = new Dictionary<ServerState, ServerState>();
            }

            // ==========================================
            // KROK 1: Inicjalizacja (Dla t = 0)
            // ==========================================
            var firstObservation = observations[0];
            foreach (var state in _states)
            {
                var logPi = _model.InitialLogProbabilities[state];
                var logEmission = _model.EmissionModels[state].GetLogProbability(firstObservation);
                
                // Prawdopodobieństwo startu + Prawdopodobieństwo wygenerowania pierwszej metryki
                viterbi[0][state] = logPi + logEmission;
            }

            // ==========================================
            // KROK 2: Rekurencja w przód (Dla t > 0)
            // ==========================================
            for (var t = 1; t < T; t++)
            {
                var currentObservation = observations[t];

                foreach (var currentState in _states)
                {
                    var maxLogProb = double.NegativeInfinity;
                    var bestPrevState = _states[0];

                    // Obliczamy emisję Gaussa tylko RAZ dla obecnego stanu i czasu 't'
                    var currentLogEmission = _model.EmissionModels[currentState].GetLogProbability(currentObservation);

                    // Szukamy najlepszej ścieżki z wczoraj (t-1) do dzisiaj (t)
                    foreach (var prevState in _states)
                    {
                        var prevLogProb = viterbi[t - 1][prevState];
                        var transitionLogProb = _model.TransitionLogProbabilities[prevState][currentState];

                        // Logika ścieżki: Prawdopodobieństwo wczoraj + Prawdopodobieństwo przejścia
                        var probPath = prevLogProb + transitionLogProb;

                        if (probPath > maxLogProb)
                        {
                            maxLogProb = probPath;
                            bestPrevState = prevState;
                        }
                    }

                    // Zapisujemy najlepszy wynik (dodając naszą pre-kalkulowaną emisję Gaussa)
                    viterbi[t][currentState] = maxLogProb + currentLogEmission;
                    backpointer[t][currentState] = bestPrevState; // Zostawiamy "okruszek chleba" do powrotu
                }
            }

            // ==========================================
            // KROK 3: Zakończenie i odtworzenie ścieżki
            // ==========================================
            var bestPath = new ServerState[T];

            var bestFinalProb = double.NegativeInfinity;
            var bestFinalState = _states[0];

            // Szukamy stanu końcowego z najwyższym prawdopodobieństwem w ostatniej sekundzie (T-1)
            foreach (var state in _states)
            {
                if (viterbi[T - 1][state] > bestFinalProb)
                {
                    bestFinalProb = viterbi[T - 1][state];
                    bestFinalState = state;
                }
            }

            bestPathLogProbability = bestFinalProb;
            bestPath[T - 1] = bestFinalState;

            // Cofamy się po "okruszkach" (backpointers) aby odtworzyć całą historię
            for (var t = T - 1; t > 0; t--)
            {
                bestPath[t - 1] = backpointer[t][bestPath[t]];
            }

            return [.. bestPath];
        }
    }
}