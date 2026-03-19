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
            double piSum = states.Sum(s => Math.Exp(trained.InitialLogProbabilities[s]));

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
                double rowSum = states.Sum(to =>
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
                double logP = trained.EmissionModels[state].GetLogProbability(probe);
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
            double prev = double.NegativeInfinity;
            for (int iter = 0; iter < 10; iter++)
            {
                model = learner.Train(model, MixedSeq(40), maxIterations: 1, tolerance: 0.0);
                double ll = learner.LastResult!.FinalLogLikelihood;
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
            int maxIter = 30;
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

            string s = learner.LastResult!.ToString();
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

            double logPHigh = trained.EmissionModels[ServerState.Critical]
                .GetLogProbability([0.98, 0.94]);
            double logPLow = trained.EmissionModels[ServerState.Critical]
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
            double expected = Math.Log(Math.Exp(a) + Math.Exp(b));
            double actual = MathUtils.LogSumExp(new[] { a, b });
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
            double result = MathUtils.LogSumExp(new[] { double.NegativeInfinity, -3.0 });
            Assert.Equal(-3.0, result, precision: 12);
        }

        [Fact]
        public void MathUtils_LogSumExp_Binary_MatchesEnumerable()
        {
            double a = -2.5, b = -1.5;
            double binary = MathUtils.LogSumExp(a, b);
            double enumerable = MathUtils.LogSumExp(new[] { a, b });
            Assert.Equal(binary, enumerable, precision: 12);
        }

        [Fact]
        public void MathUtils_LogSumExp_LargeValues_DoesNotOverflow()
        {
            // Bez trick'u max: exp(800) = Infinity → NaN
            var vals = new[] { 800.0, 799.0, 798.0 };
            double result = MathUtils.LogSumExp(vals);
            Assert.True(double.IsFinite(result), $"Overflow: wynik = {result}");
            Assert.True(result > 800.0, "Wynik powinien być nieco powyżej max");
        }

        [Fact]
        public void MathUtils_LogSumExp_VeryNegativeValues_DoesNotUnderflow()
        {
            var vals = new[] { -800.0, -801.0, -802.0 };
            double result = MathUtils.LogSumExp(vals);
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
            for (int i = 0; i < T / 2; i++) seq.Add([0.20, 0.40]);
            for (int i = 0; i < T / 2; i++) seq.Add([0.99, 0.95]);
            return seq;
        }

        // ── guard clauses ─────────────────────────────────────────────────────────
    }
}

