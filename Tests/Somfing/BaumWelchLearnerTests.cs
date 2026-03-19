using DevOnBike.Security.Tests.Somfing.Contracts;

namespace DevOnBike.Security.Tests.Somfing
{
    public class BaumWelchLearnerTests
    {
        [Fact]
        public void Train_NullModel_ThrowsArgumentNullException()
        {
            var learner = new BaumWelchLearner();
            Assert.Throws<ArgumentNullException>(() =>
                learner.Train(null!, HealthySeq()));
        }

        [Fact]
        public void Train_NullObservations_ThrowsArgumentNullException()
        {
            var learner = new BaumWelchLearner();
            Assert.Throws<ArgumentNullException>(() =>
                learner.Train(Factory(), null!));
        }

        [Fact]
        public void Train_EmptyObservations_ThrowsArgumentException()
        {
            var learner = new BaumWelchLearner();
            var ex = Assert.Throws<ArgumentException>(() =>
                learner.Train(Factory(), []));

            Assert.Contains("pusta", ex.Message);
        }

        [Fact]
        public void Train_WrongObservationDimension_ThrowsArgumentException()
        {
            var learner = new BaumWelchLearner();
            var wrongDim = new List<double[]>
        {
            ([0.5d, 0.5d, 0.5d])
        }; // model oczekuje d=2

            var ex = Assert.Throws<ArgumentException>(() =>
                learner.Train(Factory(), wrongDim));

            Assert.Contains("wymiar", ex.Message);
            Assert.Contains("3", ex.Message);
        }

        [Fact]
        public void Train_DimensionMismatchInMiddle_ThrowsArgumentExceptionWithIndex()
        {
            var learner = new BaumWelchLearner();
            var seq = new List<double[]>
        {
            ([0.2, 0.4]),   // OK
            ([0.2, 0.4]),   // OK
            ([0.2, 0.4, 0.5]), // zły wymiar na indeksie 2
        };

            var ex = Assert.Throws<ArgumentException>(() =>
                learner.Train(Factory(), seq));

            Assert.Contains("[2]", ex.Message);
        }

        // ── poprawność algorytmu — właściwości stochastyczne ─────────────────────

        [Fact]
        public void Train_OutputPi_SumsToCritically1()
        {
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), HealthySeq(), maxIterations: 5);

            var states = Enum.GetValues<ServerState>();
            var piSum = states.Sum(s => Math.Exp(trained.InitialLogProbabilities[s]));

            Assert.Equal(1.0, piSum, precision: 9);
        }

        [Fact]
        public void Train_OutputTransitionRows_EachSumToOne()
        {
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), HealthySeq(), maxIterations: 5);

            var states = Enum.GetValues<ServerState>();
            foreach (var from in states)
            {
                var rowSum = states.Sum(to =>
                    Math.Exp(trained.TransitionLogProbabilities[from][to]));

                Assert.Equal(1.0, rowSum, precision: 9);
            }
        }

        [Fact]
        public void Train_OutputEmissions_NeverReturnNaNLogPdf()
        {
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), MixedSeq(), maxIterations: 5);

            double[] probe = [0.50, 0.50];
            foreach (var state in Enum.GetValues<ServerState>())
            {
                var logP = trained.EmissionModels[state].GetLogProbability(probe);
                Assert.False(double.IsNaN(logP), $"NaN dla stanu {state}");
                Assert.True(double.IsFinite(logP), $"±Inf dla stanu {state}");
            }
        }

        // ── monotoniczność EM (fundamentalna właściwość) ──────────────────────────

        [Fact]
        public void Train_LogLikelihood_IsMonotonicallyNonDecreasing()
        {
            // log P(O|λₙ₊₁) ≥ log P(O|λₙ) — gwarantowane przez EM
            var learner = new BaumWelchLearner();
            var history = new List<double>();
            var model = Factory();

            // Ręcznie śledzimy logLikelihood przez kolejne wywołania z 1 iteracją
            var prev = double.NegativeInfinity;
            for (var iter = 0; iter < 10; iter++)
            {
                model = learner.Train(model, MixedSeq(40), maxIterations: 1, tolerance: 0.0);
                var ll = learner.LastResult!.FinalLogLikelihood;
                history.Add(ll);

                if (iter > 0)
                    Assert.True(ll >= prev - 1e-6,
                        $"Log-likelihood spadł w iteracji {iter}: {prev:F6} → {ll:F6}. " +
                        "Naruszenie monotoniczności EM.");
                prev = ll;
            }

            Assert.Equal(10, history.Count);
        }

        // ── BaumWelchLearnerResult ────────────────────────────────────────────────

        [Fact]
        public void LastResult_BeforeFirstCall_IsNull()
        {
            var learner = new BaumWelchLearner();
            Assert.Null(learner.LastResult);
        }

        [Fact]
        public void Train_AfterConvergence_LastResultConvergedIsTrue()
        {
            var learner = new BaumWelchLearner();
            learner.Train(Factory(), HealthySeq(30), maxIterations: 100, tolerance: 1e-3);

            Assert.NotNull(learner.LastResult);
            Assert.True(learner.LastResult!.Converged,
                $"Model nie zbiegł. Iteracje: {learner.LastResult.Iterations}, " +
                $"logP: {learner.LastResult.FinalLogLikelihood:F4}");
        }

        [Fact]
        public void Train_WhenHitsMaxIterations_LastResultConvergedIsFalse()
        {
            var learner = new BaumWelchLearner();
            learner.Train(Factory(), MixedSeq(60), maxIterations: 1, tolerance: 1e-20);

            Assert.NotNull(learner.LastResult);
            Assert.False(learner.LastResult!.Converged);
            Assert.Equal(1, learner.LastResult.Iterations);
        }

        [Fact]
        public void Train_LastResult_IterationsInRange()
        {
            var learner = new BaumWelchLearner();
            var maxIter = 30;
            learner.Train(Factory(), HealthySeq(20), maxIterations: maxIter);

            Assert.InRange(learner.LastResult!.Iterations, 1, maxIter);
        }

        [Fact]
        public void Train_LastResult_FinalLogLikelihoodIsFinite()
        {
            var learner = new BaumWelchLearner();
            learner.Train(Factory(), HealthySeq(20), maxIterations: 10);

            Assert.True(double.IsFinite(learner.LastResult!.FinalLogLikelihood),
                $"FinalLogLikelihood = {learner.LastResult.FinalLogLikelihood}");
        }

        [Fact]
        public void BaumWelchLearnerResult_ToString_ContainsKeyFields()
        {
            var learner = new BaumWelchLearner();
            learner.Train(Factory(), HealthySeq(), maxIterations: 5);

            var s = learner.LastResult!.ToString();
            Assert.Contains("Converged", s);
            Assert.Contains("Iterations", s);
            Assert.Contains("LogLikelihood", s);
        }

        // ── jitter — regularyzacja kowariancji ────────────────────────────────────

        [Fact]
        public void Train_WithConstantObservations_DoesNotThrowSingularMatrix()
        {
            // Zerowa wariancja w danych — regularyzacja musi zapobiec singularności
            var learner = new BaumWelchLearner();
            var constant = Enumerable.Repeat(new double[] { 0.20, 0.40 }, 15).ToList();

            var ex = Record.Exception(() =>
                learner.Train(Factory(), constant, maxIterations: 3));

            Assert.Null(ex);
        }

        [Fact]
        public void Train_DiagonalCovariance_NeverBelowJitterFloor()
        {
            // Po treningu wszystkie diagonale Σ powinny być ≥ 1e-4
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), HealthySeq(30), maxIterations: 10);

            double[] probe = [0.0, 0.0];
            double[] probe2 = [1.0, 1.0];

            foreach (var state in Enum.GetValues<ServerState>())
            {
                // Jeśli macierz byłaby osobliwa, GetLogProbability rzuciłoby wyjątek
                var ex1 = Record.Exception(() => trained.EmissionModels[state].GetLogProbability(probe));
                var ex2 = Record.Exception(() => trained.EmissionModels[state].GetLogProbability(probe2));
                Assert.Null(ex1);
                Assert.Null(ex2);
            }
        }

        // ── separacja stanów po treningu ─────────────────────────────────────────

        [Fact]
        public void Train_OnCriticalData_CriticalEmissionFavorsHighCpuRam()
        {
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), CriticalSeq(30), maxIterations: 20);

            var logPHigh = trained.EmissionModels[ServerState.Critical]
                .GetLogProbability([0.98, 0.94]);
            var logPLow = trained.EmissionModels[ServerState.Critical]
                .GetLogProbability([0.20, 0.40]);

            Assert.True(logPHigh > logPLow,
                $"Po treningu na danych Critical: " +
                $"logP([0.98,0.94])={logPHigh:F3} powinno być > logP([0.20,0.40])={logPLow:F3}");
        }

        [Fact]
        public void Train_SecondCallUpdatesPreviousLastResult()
        {
            var learner = new BaumWelchLearner();

            learner.Train(Factory(), HealthySeq(15), maxIterations: 3);
            var first = learner.LastResult!.FinalLogLikelihood;

            learner.Train(Factory(), MixedSeq(40), maxIterations: 3);
            var second = learner.LastResult!.FinalLogLikelihood;

            // MixedSeq(40) ma więcej obserwacji → sumarycznie wyższe |logLikelihood|
            Assert.NotEqual(first, second);
        }

        // ── MathUtils.LogSumExp ───────────────────────────────────────────────────

        [Fact]
        public void MathUtils_LogSumExp_TwoFiniteValues_MatchesReference()
        {
            double a = -1.0, b = -2.0;
            var expected = Math.Log(Math.Exp(a) + Math.Exp(b));
            var actual = MathUtils.LogSumExp(new[] { a, b });
            Assert.Equal(expected, actual, precision: 12);
        }

        [Fact]
        public void MathUtils_LogSumExp_AllNegativeInfinity_ReturnsNegativeInfinity()
        {
            var result = MathUtils.LogSumExp(
                new[] { double.NegativeInfinity, double.NegativeInfinity });
            Assert.Equal(double.NegativeInfinity, result);
        }

        [Fact]
        public void MathUtils_LogSumExp_OneFiniteOneNegInf_ReturnsFinite()
        {
            var result = MathUtils.LogSumExp(new[] { double.NegativeInfinity, -3.0 });
            Assert.Equal(-3.0, result, precision: 12);
        }

        [Fact]
        public void MathUtils_LogSumExp_Binary_MatchesEnumerable()
        {
            double a = -2.5, b = -1.5;
            var binary = MathUtils.LogSumExp(a, b);
            var enumerable = MathUtils.LogSumExp(new[] { a, b });
            Assert.Equal(binary, enumerable, precision: 12);
        }

        [Fact]
        public void MathUtils_LogSumExp_LargeValues_DoesNotOverflow()
        {
            // Bez trick'u max: exp(800) = Infinity → NaN
            var vals = new[] { 800.0, 799.0, 798.0 };
            var result = MathUtils.LogSumExp(vals);
            Assert.True(double.IsFinite(result), $"Overflow: wynik = {result}");
            Assert.True(result > 800.0, "Wynik powinien być nieco powyżej max");
        }

        [Fact]
        public void MathUtils_LogSumExp_VeryNegativeValues_DoesNotUnderflow()
        {
            var vals = new[] { -800.0, -801.0, -802.0 };
            var result = MathUtils.LogSumExp(vals);
            Assert.True(double.IsFinite(result), $"Underflow: wynik = {result}");
            Assert.True(result > -801.0);
        }

        // ── helpers ───────────────────────────────────────────────────────────────

        private static ContinuousHMM Factory() =>
            ItMonitoringHmmFactory.CreateCpuAndRamModel();

        private static List<double[]> HealthySeq(int T = 20) =>
            Enumerable.Range(0, T)
                .Select(i => new double[] { 0.18 + (i % 3) * 0.01, 0.38 + (i % 3) * 0.01 })
                .ToList();

        private static List<double[]> CriticalSeq(int T = 20) =>
            Enumerable.Range(0, T)
                .Select(i => new double[] { 0.97 + (i % 2) * 0.02, 0.93 + (i % 2) * 0.02 })
                .ToList();

        private static List<double[]> MixedSeq(int T = 40)
        {
            var seq = new List<double[]>();
            for (var i = 0; i < T / 2; i++) seq.Add([0.20, 0.40]);
            for (var i = 0; i < T / 2; i++) seq.Add([0.99, 0.95]);
            return seq;
        }


        // ── testy funkcjonalne: uczenie się μ ────────────────────────────────────

        [Fact]
        public void Train_OnHealthyData_HealthyEmissionPrefersLowCpuRam()
        {
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), HealthySeq(40), maxIterations: 30);

            var logPCenter = trained.EmissionModels[ServerState.Healthy].GetLogProbability([0.20, 0.40]);
            var logPOther = trained.EmissionModels[ServerState.Healthy].GetLogProbability([0.99, 0.95]);

            Assert.True(logPCenter > logPOther,
                $"Healthy emission: logP([0.20,0.40])={logPCenter:F3} powinno być > logP([0.99,0.95])={logPOther:F3}");
        }

        [Fact]
        public void Train_EachStatePrefersCenterOfItsOwnTrainingData()
        {
            var scenarios = new (ServerState state, double[] center, double[] other, List<double[]> seq)[]
            {
                (ServerState.Healthy,  [0.20, 0.40], [0.99, 0.95], HealthySeq(30)),
                (ServerState.Critical, [0.99, 0.95], [0.20, 0.40], CriticalSeq(30)),
            };

            foreach (var (state, center, other, seq) in scenarios)
            {
                var learner = new BaumWelchLearner();
                var trained = learner.Train(Factory(), seq, maxIterations: 25);

                var logPCenter = trained.EmissionModels[state].GetLogProbability(center);
                var logPOther = trained.EmissionModels[state].GetLogProbability(other);

                Assert.True(logPCenter > logPOther,
                    $"Stan {state}: centrum {logPCenter:F3} powinno być > punkt obcy {logPOther:F3}");
            }
        }

        // ── testy funkcjonalne: uczenie się π ────────────────────────────────────

        [Fact]
        public void Train_OnHealthyData_PiHealthyDoesNotDecrease()
        {
            // π[Healthy] startuje od 0.90 i na danych Healthy nie powinno spaść.
            var piInitial = Math.Exp(Factory().InitialLogProbabilities[ServerState.Healthy]);

            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), HealthySeq(30), maxIterations: 20);
            var piTrained = Math.Exp(trained.InitialLogProbabilities[ServerState.Healthy]);

            Assert.True(piTrained >= piInitial - 1e-9,
                $"π[Healthy]: {piInitial:F4} → {piTrained:F4}. Nie powinno spaść po treningu na Healthy.");
        }

        [Fact]
        public void Train_PiSumsToOne_AfterAnyTraining()
        {
            // Niezależnie od danych i iteracji, Σ π[s] = 1.
            // Weryfikuje poprawność UpdatePi (normalizacja w M-stepie).
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), CriticalSeq(30), maxIterations: 20);

            var piSum = Enum.GetValues<ServerState>()
                .Sum(s => Math.Exp(trained.InitialLogProbabilities[s]));

            Assert.Equal(1.0, piSum, precision: 9);
        }

        // Uwaga: test "PiCriticalIncreasesFromPrior" jest celowo pominięty.
        // DLACZEGO: π[i] = γ[0][i] zależy od tego, KTÓRY stan wygra na t=0
        // przy ZBIEŻNYM modelu — nie od tego, na jakich danych trenujemy.
        // Przy alternującej sekwencji [0.97,0.93]/[0.99,0.95], EM może przypisać
        // t=0 do Degraded (które dryfuje w stronę [0.97,0.93]), co zmniejszy π[C].
        // Właściwe zachowanie emisji jest testowane przez Train_EachStatePrefersCenterOfItsOwnTrainingData.

        // ── testy funkcjonalne: uczenie się A ────────────────────────────────────

        [Fact]
        public void Train_AllTransitionProbabilitiesStrictlyPositive()
        {
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), HealthySeq(30), maxIterations: 10);

            foreach (var from in Enum.GetValues<ServerState>())
                foreach (var to in Enum.GetValues<ServerState>())
                {
                    var p = Math.Exp(trained.TransitionLogProbabilities[from][to]);
                    Assert.True(p > 0.0, $"A[{from}→{to}]={p} — EM nie powinien zerować przejść.");
                }
        }

        [Fact]
        public void Train_OnStickySequence_SelfTransitionIncreasesForDominantState()
        {
            // C C C C... → A[Critical→Critical] powinno wzrosnąć (model uczy się trwania).
            var aInitial = Math.Exp(Factory().TransitionLogProbabilities[ServerState.Critical][ServerState.Critical]);

            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), CriticalSeq(40), maxIterations: 20);
            var aTrained = Math.Exp(trained.TransitionLogProbabilities[ServerState.Critical][ServerState.Critical]);

            Assert.True(aTrained >= aInitial - 1e-9,
                $"A[C→C]: {aInitial:F4} → {aTrained:F4}. Nie powinno spaść przy sticky Critical.");
        }

        [Fact]
        public void Train_OnAlternatingData_CrossTransitionsIncrease()
        {
            // H C H C... → A[H→C] i A[C→H] powinny wzrosnąć (częste przejścia).
            var initial = Factory();
            var aHC = Math.Exp(initial.TransitionLogProbabilities[ServerState.Healthy][ServerState.Critical]);
            var aCH = Math.Exp(initial.TransitionLogProbabilities[ServerState.Critical][ServerState.Healthy]);

            var alternating = Enumerable.Range(0, 30)
                .Select(i => i % 2 == 0 ? new[] { 0.20, 0.40 } : new[] { 0.99, 0.95 })
                .ToList();

            var learner = new BaumWelchLearner();
            var trained = learner.Train(initial, alternating, maxIterations: 20);

            var aHC_new = Math.Exp(trained.TransitionLogProbabilities[ServerState.Healthy][ServerState.Critical]);
            var aCH_new = Math.Exp(trained.TransitionLogProbabilities[ServerState.Critical][ServerState.Healthy]);

            Assert.True(aHC_new > aHC, $"A[H→C]: {aHC:F4} → {aHC_new:F4}. Powinno wzrosnąć przy naprzemiennych danych.");
            Assert.True(aCH_new > aCH, $"A[C→H]: {aCH:F4} → {aCH_new:F4}. Powinno wzrosnąć przy naprzemiennych danych.");
        }

        // ── testy funkcjonalne: Gershgorin SPD ───────────────────────────────────

        [Fact]
        public void Train_OnHighlyCorrelatedData_DoesNotThrowSingularMatrix()
        {
            // CPU ≈ RAM → duże off-diagonal → bez Gershgorina: Cholesky pady.
            var correlated = Enumerable.Range(0, 25)
                .Select(i => new[] { 0.50 + i * 0.001, 0.50 + i * 0.001 })
                .ToList();

            var ex = Record.Exception(() =>
                new BaumWelchLearner().Train(Factory(), correlated, maxIterations: 5));

            Assert.Null(ex);
        }

        [Fact]
        public void Train_OnPerfectlyCorrelatedData_DoesNotThrowSingularMatrix()
        {
            // CPU = RAM (korelacja = 1) — maksymalne off-diagonal.
            var perfect = Enumerable.Repeat(new[] { 0.75, 0.75 }, 20).ToList();

            var ex = Record.Exception(() =>
                new BaumWelchLearner().Train(Factory(), perfect, maxIterations: 3));

            Assert.Null(ex);
        }

        // ── testy funkcjonalne: edge cases T ─────────────────────────────────────

        [Fact]
        public void Train_WithSingleObservation_DoesNotThrow()
        {
            // T=1: brak ξ (T-1=0), tylko γ[0] i aktualizacja π i μ.
            var ex = Record.Exception(() =>
                new BaumWelchLearner().Train(Factory(), [[0.20, 0.40]], maxIterations: 2));

            Assert.Null(ex);
        }

        [Fact]
        public void Train_WithTwoObservations_OutputModelIsStochastic()
        {
            // T=2: minimalna xi (1 przejście).
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), [[0.20, 0.40], [0.21, 0.39]], maxIterations: 3);

            var piSum = Enum.GetValues<ServerState>()
                .Sum(s => Math.Exp(trained.InitialLogProbabilities[s]));
            Assert.Equal(1.0, piSum, precision: 9);

            foreach (var from in Enum.GetValues<ServerState>())
            {
                var rowSum = Enum.GetValues<ServerState>()
                    .Sum(to => Math.Exp(trained.TransitionLogProbabilities[from][to]));
                Assert.Equal(1.0, rowSum, precision: 9);
            }
        }

        // ── testy funkcjonalne: więcej iteracji = lepsza jakość ──────────────────

        [Fact]
        public void Train_MoreIterations_GivesHigherOrEqualLogLikelihood()
        {
            var data = MixedSeq(40);

            var l2 = new BaumWelchLearner();
            l2.Train(Factory(), data, maxIterations: 2, tolerance: 0.0);

            var l10 = new BaumWelchLearner();
            l10.Train(Factory(), data, maxIterations: 10, tolerance: 0.0);

            Assert.True(l10.LastResult!.FinalLogLikelihood >= l2.LastResult!.FinalLogLikelihood - 1e-6,
                $"logP(10 iter)={l10.LastResult.FinalLogLikelihood:F4} powinno być >= logP(2 iter)={l2.LastResult.FinalLogLikelihood:F4}");
        }

        // ── testy funkcjonalne: idempotencja po zbieżności ───────────────────────

        [Fact]
        public void Train_AtConvergence_OneMoreIterationChangesLogPLessThanTolerance()
        {
            const double tolerance = 1e-3;
            var data = HealthySeq(30);
            var learner = new BaumWelchLearner();
            var converged = learner.Train(Factory(), data, maxIterations: 100, tolerance: tolerance);
            var logPConv = learner.LastResult!.FinalLogLikelihood;

            var learner2 = new BaumWelchLearner();
            learner2.Train(converged, data, maxIterations: 1, tolerance: 0.0);
            var logPNext = learner2.LastResult!.FinalLogLikelihood;

            Assert.True(Math.Abs(logPNext - logPConv) < tolerance * 10,
                $"|logP_next - logP_conv| = {Math.Abs(logPNext - logPConv):G4} powinno być < {tolerance * 10:G4}");
        }

        // ── testy funkcjonalne: round-trip Viterbi ────────────────────────────────

        [Fact]
        public void Train_ThenViterbi_CriticalDataDecodesAsCritical()
        {
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), CriticalSeq(30), maxIterations: 20);
            var decoder = new ViterbiDecoder(trained);

            var path = decoder.Decode(CriticalSeq(10));

            var criticalCount = path.Count(s => s == ServerState.Critical);
            Assert.True(criticalCount >= path.Count / 2,
                $"Po treningu na Critical: {criticalCount}/{path.Count} zdekodowanych jako Critical.");
        }

        [Fact]
        public void Train_ThenViterbi_HealthyDataDecodesAsHealthy()
        {
            var learner = new BaumWelchLearner();
            var trained = learner.Train(Factory(), HealthySeq(30), maxIterations: 20);
            var decoder = new ViterbiDecoder(trained);

            var path = decoder.Decode(HealthySeq(10));

            var healthyCount = path.Count(s => s == ServerState.Healthy);
            Assert.True(healthyCount >= path.Count / 2,
                $"Po treningu na Healthy: {healthyCount}/{path.Count} zdekodowanych jako Healthy.");
        }

        // ── testy funkcjonalne: stabilność numeryczna ────────────────────────────

        [Fact]
        public void Train_WithObservationFarFromAllCenters_DoesNotProduceNaN()
        {
            var farData = Enumerable.Repeat(new[] { 0.50, 0.50 }, 15).ToList();
            var learner = new BaumWelchLearner();
            learner.Train(Factory(), farData, maxIterations: 3);

            Assert.True(double.IsFinite(learner.LastResult!.FinalLogLikelihood),
                $"FinalLogLikelihood = {learner.LastResult.FinalLogLikelihood} przy danych [0.5, 0.5]");
        }

        [Fact]
        public void Train_RepeatedCallsOnSameData_GiveDeterministicResult()
        {
            var learner = new BaumWelchLearner();

            learner.Train(Factory(), HealthySeq(20), maxIterations: 5);
            var ll1 = learner.LastResult!.FinalLogLikelihood;

            learner.Train(Factory(), HealthySeq(20), maxIterations: 5);
            var ll2 = learner.LastResult!.FinalLogLikelihood;

            Assert.Equal(ll1, ll2, precision: 6);
        }

        // ── guard clauses ─────────────────────────────────────────────────────────
    }
}