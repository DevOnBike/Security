namespace DevOnBike.Security.Tests.Somfing
{
    public class CholeskyMultivariateGaussian
    {
        private readonly double[] _mean;
        private readonly double[,] _L; // Macierz trójkątna dolna z rozkładu Cholesky'ego
        private readonly double _coefficient;
        private readonly int _dimensions;

        public CholeskyMultivariateGaussian(double[] mean, double[,] covariance)
        {
            _dimensions = mean.Length;
            _mean = mean;

            // Wykonujemy rozkład Cholesky'ego: covariance = L * L^T
            _L = DecomposeCholesky(covariance);

            // Wyznacznik to kwadrat iloczynu elementów na przekątnej macierzy L
            double detSqrt = 1.0;

            for (int i = 0; i < _dimensions; i++)
            {
                detSqrt *= _L[i, i];
            }

            var determinant = detSqrt * detSqrt;

            // Współczynnik przed funkcją exp()
            _coefficient = 1.0 / (Math.Sqrt(Math.Pow(2 * Math.PI, _dimensions)) * detSqrt);
        }

        public double ProbabilityDensity(double[] observation)
        {
            // 1. Różnica (x - μ)
            double[] diff = new double[_dimensions];

            for (int i = 0; i < _dimensions; i++)
            {
                diff[i] = observation[i] - _mean[i];
            }

            // 2. Rozwiązujemy układ równań L * z = diff za pomocą podstawiania w przód (Forward Substitution).
            // To jest błyskawiczne, bo L jest macierzą trójkątną dolną!
            double[] z = new double[_dimensions];

            for (int i = 0; i < _dimensions; i++)
            {
                double sum = 0;
                for (int j = 0; j < i; j++)
                {
                    sum += _L[i, j] * z[j];
                }

                z[i] = (diff[i] - sum) / _L[i, i];
            }

            // 3. Iloczyn skalarny z^T * z (odpowiada to wyrażeniu (x-μ)^T * Σ^-1 * (x-μ))
            double exponentTerm = 0;
            for (int i = 0; i < _dimensions; i++)
            {
                exponentTerm += z[i] * z[i];
            }

            return _coefficient * Math.Exp(-0.5 * exponentTerm);
        }

        /// <summary>
        /// Rozkład Cholesky-Banachiewicza. 
        /// Przekształca macierz symetryczną dodatnio określoną w dolną macierz trójkątną L.
        /// </summary>
        private static double[,] DecomposeCholesky(double[,] matrix)
        {
            int n = matrix.GetLength(0);
            double[,] L = new double[n, n];

            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j <= i; j++)
                {
                    double sum = 0;
                    for (int k = 0; k < j; k++)
                    {
                        sum += L[i, k] * L[j, k];
                    }

                    if (i == j)
                    {
                        double val = matrix[i, i] - sum;

                        if (val <= 0)
                        {
                            // To zabezpieczenie zadziała, jeśli np. wrzucimy logi, 
                            // w których RAM i CPU są w 100% identyczne co do ułamka (idealna korelacja).
                            throw new ArgumentException("Macierz kowariancji nie jest dodatnio określona!");
                        }
                        L[i, i] = Math.Sqrt(val);
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

