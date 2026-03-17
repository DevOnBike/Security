namespace DevOnBike.Security.Tests.Somfing
{
    /// <summary>
    /// Wielowymiarowy rozkład Gaussa N(μ, Σ) z rozkładem Cholesky'ego.
    ///
    /// POPRAWKI względem oryginału:
    ///   1. Overflow: Math.Pow(2π,d) → infinity dla d≳150.
    ///      Naprawione: współczynnik normalizujący w przestrzeni logarytmicznej (_logNormConst).
    ///   2. Martwa zmienna `determinant` — usunięta.
    ///   3. Brak defensive copy _mean — naprawione (.ToArray()).
    ///   4. Brak walidacji wejść w konstruktorze — dodane guard clauses.
    ///   5. Brak walidacji observation w ProbabilityDensity — dodane.
    ///   6. Dodano LogProbabilityDensity — numerycznie stabilniejsze dla małych p.
    /// </summary>
    public class CholeskyMultivariateGaussian
    {
        private readonly double[] _mean;
        private readonly double[,] _L; // dolna macierz trójkątna: Σ = L·Lᵀ
        private readonly double _logNormConst; // −½·(d·ln2π + ln|Σ|)
        private readonly int _dimensions;

        public CholeskyMultivariateGaussian(double[] mean, double[,] covariance)
        {
            ArgumentNullException.ThrowIfNull(mean);
            ArgumentNullException.ThrowIfNull(covariance);

            var n = mean.Length;

            if (n == 0)
            {
                throw new ArgumentException("Wektor średniej nie może być pusty.", nameof(mean));
            }

            if (covariance.GetLength(0) != n || covariance.GetLength(1) != n)
            {
                throw new ArgumentException($"Macierz kowariancji musi być {n}×{n}, podano {covariance.GetLength(0)}×{covariance.GetLength(1)}.", nameof(covariance));
            }

            _dimensions = n;
            _mean = [.. mean]; // defensive copy — mutacja zewnętrznego bufora nie zmienia stanu

            _L = DecomposeCholesky(covariance);

            // ── współczynnik normalizujący w log-space ───────────────────────────
            //
            // PROBLEM oryginalnego kodu:
            //   _coefficient = 1 / (sqrt(pow(2π,d)) * detSqrt)
            //   Math.Pow(2π, d) → +Infinity dla d ≳ 150 (podwójna precyzja: max ≈ 10^308)
            //   Wtedy _coefficient = 0, a ProbabilityDensity zwraca 0 dla każdego wektora.
            //
            // ROZWIĄZANIE: przechowujemy log-stałą i aplikujemy Math.Exp dopiero w ProbabilityDensity.
            //
            //   logNormConst = −½·d·ln(2π) − Σᵢ ln L[i,i]
            //
            // Człon Σᵢ ln L[i,i] = ½·ln|Σ|, bo ln|Σ| = ln|L·Lᵀ| = 2·Σᵢ ln L[i,i].
            // Zakres logarytmów jest dobrze ograniczony dla każdego rozsądnego d.
            _logNormConst = -0.5 * _dimensions * Math.Log(2.0 * Math.PI);

            for (var i = 0; i < _dimensions; i++)
            {
                _logNormConst -= Math.Log(_L[i, i]);
            }
        }

        // ── API publiczne ────────────────────────────────────────────────────────

        /// <summary>
        /// Wartość gęstości prawdopodobieństwa p(x) dla podanej obserwacji.
        /// </summary>
        public double ProbabilityDensity(double[] observation)
        {
            return Math.Exp(LogProbabilityDensity(observation));
        }

        /// <summary>
        /// Logarytm naturalny gęstości ln p(x).
        /// Preferowane do bezpośredniego użytku w HMM — unika przepełnienia/niedomiaru.
        /// </summary>
        public double LogProbabilityDensity(double[] observation)
        {
            if (observation is null || observation.Length != _dimensions)
            {
                throw new ArgumentException($"Obserwacja musi mieć długość {_dimensions}.", nameof(observation));
            }

            // 1. diff = x − μ
            var diff = new double[_dimensions];
            
            for (var i = 0; i < _dimensions; i++)
            {
                diff[i] = observation[i] - _mean[i];
            }

            // 2. Forward substitution: L·z = diff
            //    L jest dolna trójkątna → O(d²/2) mnożeń
            var z = new double[_dimensions];
            for (var i = 0; i < _dimensions; i++)
            {
                var sum = 0.0;
                
                for (var j = 0; j < i; j++)
                {
                    sum += _L[i, j] * z[j];
                }

                z[i] = (diff[i] - sum) / _L[i, i];
            }

            // 3. δ² = zᵀ·z = (x−μ)ᵀ·Σ⁻¹·(x−μ)  (odległość Mahalanobisa do kwadratu)
            var mahalSq = 0.0;
            for (var i = 0; i < _dimensions; i++)
            {
                mahalSq += z[i] * z[i];
            }

            // 4. ln p(x) = logNormConst − ½·δ²
            return _logNormConst - 0.5 * mahalSq;
        }

        /// <summary>
        /// Rozkład Cholesky-Banachiewicza: A = L·Lᵀ.
        /// Działa tylko dla macierzy symetrycznych dodatnio określonych.
        /// Rzuca ArgumentException, jeśli pivot ≤ 0 (macierz osobliwa lub niedodatnio określona).
        /// </summary>
        private static double[,] DecomposeCholesky(double[,] matrix)
        {
            var n = matrix.GetLength(0);
            var L = new double[n, n];

            for (var i = 0; i < n; i++)
            {
                for (var j = 0; j <= i; j++)
                {
                    var sum = 0.0;
                    
                    for (var k = 0; k < j; k++)
                    {
                        sum += L[i, k] * L[j, k];
                    }

                    if (i == j)
                    {
                        var pivot = matrix[i, i] - sum;

                        if (pivot <= 0.0)
                            throw new ArgumentException($"Macierz kowariancji nie jest dodatnio określona! Ujemny pivot [{i},{i}] = {pivot:G6}. Sprawdź czy wiersze/kolumny nie są idealnie skorelowane.", nameof(matrix));

                        L[i, i] = Math.Sqrt(pivot);
                    }
                    else
                    {
                        L[i, j] = (matrix[i, j] - sum) / L[j, j];
                    }
                }
            }

            return L;
        }
    }
}