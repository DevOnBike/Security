using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    /// <summary>
    /// Algorytm Baum-Welch (EM) do trenowania parametrów λ = (π, A, μ, Σ).
    ///
    /// Struktura metod:
    ///   Train()                   — orkiestrator: walidacja + pętla EM + zbieżność
    ///   ├─ ValidateInputs()       — guard clauses
    ///   ├─ ComputeForward()       — E-step: α[t][s] + log P(O|λ)
    ///   ├─ ComputeBackward()      — E-step: β[t][s]
    ///   ├─ ComputeGammaXi()       — E-step: γ[t][s]  ξ[t][s→s']
    ///   ├─ ComputeMStep()         — M-step: buduje nowe ContinuousHMM
    ///   │   ├─ UpdatePi()         — nowe π
    ///   │   ├─ UpdateTransitions()— nowa macierz A
    ///   │   └─ UpdateGaussian()   — nowe μ i Σ
    ///   └─ EnforceSpdGershgorin() — regularyzacja SPD kowariancji
    /// </summary>
    public class BaumWelchLearner
    {
        private const double MinVariance = 1e-4;

        private readonly ServerState[] _states = Enum.GetValues<ServerState>();

        /// <summary>Wynik ostatniego wywołania Train().</summary>
        public BaumWelchLearnerResult? LastResult { get; private set; }

        // ── publiczne API ─────────────────────────────────────────────────────

        /// <param name="initialModel">Model startowy λ₀ — punkt startowy EM.</param>
        /// <param name="observations">Sekwencja obserwacji (np. metryki z ostatnich 24h).</param>
        /// <param name="maxIterations">Maksymalna liczba iteracji EM.</param>
        /// <param name="tolerance">Próg zbieżności: |logP(n) − logP(n−1)| &lt; tolerance → stop.</param>
        public ContinuousHMM Train(
            ContinuousHMM initialModel,
            List<double[]> observations,
            int maxIterations = 50,
            double tolerance = 1e-4)
        {
            ValidateInputs(initialModel, observations);

            var T = observations.Count;
            var N = _states.Length;
            var D = observations[0].Length;

            var currentModel = initialModel;
            var previousLogLikelihood = double.NegativeInfinity;

            // Bufor N-elementowy wielokrotnego użytku — eliminuje O(T×N) alokacji List<double>
            var logProbBuf = new double[N];

            for (var iter = 0; iter < maxIterations; iter++)
            {
                // ── E-step ────────────────────────────────────────────────────
                var (alpha, logLikelihood) = ComputeForward(currentModel, observations, logProbBuf, T, N);
                var beta = ComputeBackward(currentModel, observations, logProbBuf, T, N);
                var (gamma, xi) = ComputeGammaXi(alpha, beta, logLikelihood, currentModel, observations, T);

                // ── M-step ────────────────────────────────────────────────────
                currentModel = ComputeMStep(gamma, xi, observations, T, N, D);

                // ── zbieżność ─────────────────────────────────────────────────
                if (Math.Abs(logLikelihood - previousLogLikelihood) < tolerance)
                {
                    LastResult = new BaumWelchLearnerResult
                    {
                        Converged = true,
                        Iterations = iter + 1,
                        FinalLogLikelihood = logLikelihood
                    };
                    break;
                }

                previousLogLikelihood = logLikelihood;

                if (iter == maxIterations - 1)
                {
                    LastResult = new BaumWelchLearnerResult
                    {
                        Converged = false,
                        Iterations = maxIterations,
                        FinalLogLikelihood = logLikelihood
                    };
                }
            }

            return currentModel;
        }

        // ── walidacja ─────────────────────────────────────────────────────────

        private static void ValidateInputs(ContinuousHMM model, List<double[]> observations)
        {
            ArgumentNullException.ThrowIfNull(model);
            ArgumentNullException.ThrowIfNull(observations);

            if (observations.Count == 0)
            {
                throw new ArgumentException("Lista obserwacji nie może być pusta.", nameof(observations));
            }

            var expectedDim = 0;
            foreach (var kvp in model.EmissionModels)
            {
                expectedDim = kvp.Value.Dimension;
                break;
            }
            for (var idx = 0; idx < observations.Count; idx++)
            {
                if (observations[idx].Length != expectedDim)
                {
                    throw new ArgumentException(
                        $"Obserwacja [{idx}] ma wymiar {observations[idx].Length}, oczekiwano {expectedDim}.",
                        nameof(observations));
                }
            }
        }

        // ── E-step: Forward ───────────────────────────────────────────────────

        /// <summary>
        /// α[0][s] = ln π[s] + ln B[s](o₀)
        /// α[t][s] = LogSumExp_i(α[t-1][i] + ln A[i→s]) + ln B[s](oₜ)
        /// Zwraca α i log P(O|λ) = LogSumExp_s(α[T-1][s]).
        /// </summary>
        private (Dictionary<ServerState, double>[] alpha, double logLikelihood) ComputeForward(
            ContinuousHMM model,
            List<double[]> observations,
            double[] logProbBuf,
            int T,
            int N)
        {
            var alpha = InitDictArray(T);

            foreach (var state in _states)
            {
                alpha[0][state] = model.InitialLogProbabilities[state]
                                + model.EmissionModels[state].GetLogProbability(observations[0]);
            }

            for (var t = 1; t < T; t++)
            {
                foreach (var currState in _states)
                {
                    for (var k = 0; k < N; k++)
                    {
                        logProbBuf[k] = alpha[t - 1][_states[k]]
                                      + model.TransitionLogProbabilities[_states[k]][currState];
                    }

                    alpha[t][currState] = MathUtils.LogSumExp(logProbBuf)
                                        + model.EmissionModels[currState].GetLogProbability(observations[t]);
                }
            }

            for (var k = 0; k < N; k++)
            {
                logProbBuf[k] = alpha[T - 1][_states[k]];
            }

            var logLikelihood = MathUtils.LogSumExp(logProbBuf);
            return (alpha, logLikelihood);
        }

        // ── E-step: Backward ──────────────────────────────────────────────────

        /// <summary>
        /// β[T-1][s] = 0  (= log 1)
        /// β[t][s]   = LogSumExp_j(ln A[s→j] + ln B[j](oₜ₊₁) + β[t+1][j])
        /// </summary>
        private Dictionary<ServerState, double>[] ComputeBackward(
            ContinuousHMM model,
            List<double[]> observations,
            double[] logProbBuf,
            int T,
            int N)
        {
            var beta = InitDictArray(T);

            foreach (var state in _states)
            {
                beta[T - 1][state] = 0.0; // log(1)
            }

            for (var t = T - 2; t >= 0; t--)
            {
                foreach (var currState in _states)
                {
                    for (var k = 0; k < N; k++)
                    {
                        logProbBuf[k] = model.TransitionLogProbabilities[currState][_states[k]]
                                      + model.EmissionModels[_states[k]].GetLogProbability(observations[t + 1])
                                      + beta[t + 1][_states[k]];
                    }

                    beta[t][currState] = MathUtils.LogSumExp(logProbBuf);
                }
            }

            return beta;
        }

        // ── E-step: γ i ξ ────────────────────────────────────────────────────

        /// <summary>
        /// log ξ[t][i][j] = α[t][i] + ln A[i→j] + ln B[j](oₜ₊₁) + β[t+1][j] − log P(O|λ)
        ///
        /// log γ[t][i] wyprowadzamy Z ξ dla t &lt; T−1:
        ///   log γ[t][i] = LogSumExp_j(log ξ[t][i][j])
        ///
        /// Dla t = T−1 (brak ξ): log γ[T-1][i] = α[T-1][i] + β[T-1][i] − log P(O|λ)
        ///
        /// DLACZEGO to ważne (spójność γ-ξ):
        ///   Rabiner 1989: γ_t(i) ≡ Σ_j ξ_t(i,j)
        ///   Obliczanie γ niezależnie przez α+β daje ten sam wynik matematycznie,
        ///   ale wprowadza dwie niezależne ścieżki numeryczne — mianownik UpdateTransitions
        ///   (z γ) i licznik (z ξ) mogą różnić się o ~1e-15.
        ///   Przy derywacji γ z ξ mianownik UpdateTransitions jest DOKŁADNIE sumą
        ///   marginalną licznika: Σ_t γ[t][i] = Σ_t Σ_j ξ[t][i][j] — gwarantuje
        ///   że wiersze A_new sumują się do 1 z dokładnością maszynową.
        /// </summary>
        private (Dictionary<ServerState, double>[] gamma, Dictionary<ServerState, Dictionary<ServerState, double>>[] xi) ComputeGammaXi(
            Dictionary<ServerState, double>[] alpha,
            Dictionary<ServerState, double>[] beta,
            double logLikelihood,
            ContinuousHMM model,
            List<double[]> observations,
            int T)
        {
            var gamma = InitDictArray(T);
            var xi = new Dictionary<ServerState, Dictionary<ServerState, double>>[T - 1];

            // ── t = 0 .. T-2: oblicz ξ, następnie wyprowadź γ z ξ ────────────
            for (var t = 0; t < T - 1; t++)
            {
                xi[t] = new Dictionary<ServerState, Dictionary<ServerState, double>>();

                foreach (var fromState in _states)
                {
                    xi[t][fromState] = new Dictionary<ServerState, double>();

                    foreach (var toState in _states)
                    {
                        xi[t][fromState][toState] =
                            alpha[t][fromState]
                            + model.TransitionLogProbabilities[fromState][toState]
                            + model.EmissionModels[toState].GetLogProbability(observations[t + 1])
                            + beta[t + 1][toState]
                            - logLikelihood;
                    }
                }

                // γ[t][i] = LogSumExp_j(ξ[t][i][j]) — wyprowadzone z ξ, nie z α+β
                // gwarantuje: Σ_t γ[t][i] ≡ Σ_t Σ_j ξ[t][i][j] z dokładnością maszynową
                foreach (var fromState in _states)
                {
                    gamma[t][fromState] = MathUtils.LogSumExp(xi[t][fromState].Values);
                }
            }

            // ── t = T-1: brak ξ → γ wyłącznie z α+β ─────────────────────────
            foreach (var state in _states)
            {
                gamma[T - 1][state] = alpha[T - 1][state] + beta[T - 1][state] - logLikelihood;
            }

            return (gamma, xi);
        }

        // ── M-step ────────────────────────────────────────────────────────────

        /// <summary>
        /// Buduje nowy ContinuousHMM z aktualizacjami π, A, μ, Σ dla każdego stanu.
        /// </summary>
        private ContinuousHMM ComputeMStep(
            Dictionary<ServerState, double>[] gamma,
            Dictionary<ServerState, Dictionary<ServerState, double>>[] xi,
            List<double[]> observations,
            int T,
            int N,
            int D)
        {
            var newInitProbs = new Dictionary<ServerState, double>();
            var newTransProbs = new Dictionary<ServerState, Dictionary<ServerState, double>>();
            var newEmissions = new Dictionary<ServerState, IEmissionModel>();

            foreach (var state in _states)
            {
                newInitProbs[state] = UpdatePi(gamma, state);
                newTransProbs[state] = UpdateTransitions(gamma, xi, state, T);

                var (newMean, newCov) = UpdateGaussian(gamma, observations, state, T, D);
                EnforceSpdGershgorin(newCov, D);
                newEmissions[state] = new CholeskyMultivariateGaussian(newMean, newCov);
            }

            return new ContinuousHMM(newInitProbs, newTransProbs, newEmissions);
        }

        /// <summary>π_new[s] = exp(γ[0][s]).</summary>
        private static double UpdatePi(
            Dictionary<ServerState, double>[] gamma,
            ServerState state)
        {
            return Math.Exp(gamma[0][state]);
        }

        /// <summary>
        /// A_new[s][j] = Σₜ ξ[t][s→j] / Σₜ₌₀ᵀ⁻² γ[t][s]  — w log-space, zwracane liniowo.
        ///
        /// Ponieważ γ[t&lt;T-1] jest wyprowadzone z ξ (w ComputeGammaXi),
        /// mianownik Σ_t γ[t][i] jest dokładnie Σ_t Σ_j ξ[t][i][j] z dokładnością maszynową.
        ///
        /// Edge case T=1: xi puste → LogSumExp([]) = −∞ → exp(−∞−(−∞)) = NaN.
        /// Przy T=1 nie ma obserwowanych przejść — zwracamy rozkład jednostajny.
        /// </summary>
        private Dictionary<ServerState, double> UpdateTransitions(
            Dictionary<ServerState, double>[] gamma,
            Dictionary<ServerState, Dictionary<ServerState, double>>[] xi,
            ServerState fromState,
            int T)
        {
            var row = new Dictionary<ServerState, double>();

            // T=1: xi jest puste — brak obserwowanych przejść.
            // Zwracamy rozkład jednostajny jako neutral prior.
            if (xi.Length == 0)
            {
                var uniform = 1.0 / _states.Length;
                foreach (var toState in _states)
                {
                    row[toState] = uniform;
                }
                return row;
            }

            var gammaBuf = new double[T - 1];
            for (var t = 0; t < T - 1; t++)
            {
                gammaBuf[t] = gamma[t][fromState];
            }

            var gammaSumLog = MathUtils.LogSumExp(gammaBuf);

            foreach (var toState in _states)
            {
                var xiBuf = new double[xi.Length];
                for (var t = 0; t < xi.Length; t++)
                {
                    xiBuf[t] = xi[t][fromState][toState];
                }

                var xiSumLog = MathUtils.LogSumExp(xiBuf);
                row[toState] = Math.Exp(xiSumLog - gammaSumLog);
            }

            return row;
        }

        /// <summary>
        /// μ_new[s] = Σₜ w[t]·oₜ
        /// Σ_new[s] = Σₜ w[t]·(oₜ−μ)(oₜ−μ)ᵀ    gdzie w[t] = γ[t][s] / Σₜ γ[t][s]
        /// </summary>
        private static (double[] mean, double[,] cov) UpdateGaussian(
            Dictionary<ServerState, double>[] gamma,
            List<double[]> observations,
            ServerState state,
            int T,
            int D)
        {
            var newMean = new double[D];
            var newCov = new double[D, D];
            var gammaSumBuf = new double[T];
            for (var t = 0; t < T; t++)
            {
                gammaSumBuf[t] = gamma[t][state];
            }

            var gammaSumAllLog = MathUtils.LogSumExp(gammaSumBuf);

            for (var t = 0; t < T; t++)
            {
                var weight = Math.Exp(gamma[t][state] - gammaSumAllLog);
                for (var d = 0; d < D; d++)
                {
                    newMean[d] += weight * observations[t][d];
                }
            }

            for (var t = 0; t < T; t++)
            {
                var weight = Math.Exp(gamma[t][state] - gammaSumAllLog);
                for (var d1 = 0; d1 < D; d1++)
                {
                    for (var d2 = 0; d2 < D; d2++)
                    {
                        newCov[d1, d2] += weight
                            * (observations[t][d1] - newMean[d1])
                            * (observations[t][d2] - newMean[d2]);
                    }
                }
            }

            return (newMean, newCov);
        }

        // ── regularyzacja SPD — Gershgorin ────────────────────────────────────

        /// <summary>
        /// Wymusza diagonalną dominację: diag[k] ≥ Σ_{l≠k} |cov[k,l]| + MinVariance.
        ///
        /// Math.Max(diag, MinVariance) nie wystarcza gdy off-diagonal są duże:
        ///   [[1e-4, 3e-3],[3e-3, 1e-4]] → pivot Cholesky = 1e-4 − 0.09 &lt; 0 → ArgumentException.
        /// Warunek Gershgorina gwarantuje SPD — Cholesky zawsze powiedzie się.
        /// </summary>
        private static void EnforceSpdGershgorin(double[,] cov, int D)
        {
            for (var k = 0; k < D; k++)
            {
                var offDiagSum = 0.0;
                for (var l = 0; l < D; l++)
                {
                    if (l != k)
                    {
                        offDiagSum += Math.Abs(cov[k, l]);
                    }
                }

                cov[k, k] = Math.Max(cov[k, k], offDiagSum + MinVariance);
            }
        }

        // ── helper ────────────────────────────────────────────────────────────

        private static Dictionary<ServerState, double>[] InitDictArray(int size)
        {
            var arr = new Dictionary<ServerState, double>[size];
            for (var i = 0; i < size; i++)
            {
                arr[i] = new Dictionary<ServerState, double>();
            }
            return arr;
        }
    }
}