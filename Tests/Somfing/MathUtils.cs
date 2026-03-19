namespace DevOnBike.Security.Tests.Somfing
{
    public static class MathUtils
    {
        /// <summary>
        /// Bezpieczne dodawanie prawdopodobieństw w przestrzeni logarytmicznej: log(exp(a) + exp(b))
        /// </summary>
        public static double LogSumExp(double logA, double logB)
        {
            if (double.IsNegativeInfinity(logA))
            {
                return logB;
            }

            if (double.IsNegativeInfinity(logB))
            {
                return logA;
            }

            var max = Math.Max(logA, logB);
            var min = Math.Min(logA, logB);

            return max + Math.Log(1.0 + Math.Exp(min - max));
        }

        /// <summary>
        /// LogSumExp dla całej tablicy/listy wartości.
        /// </summary>
        public static double LogSumExp(IEnumerable<double> values)
        {
            var max = double.NegativeInfinity;

            foreach (var v in values)
            {
                if (v > max)
                {
                    max = v;
                }
            }

            if (double.IsNegativeInfinity(max))
            {
                return max;
            }

            var sum = 0.0;

            foreach (var v in values)
            {
                if (!double.IsNegativeInfinity(v))
                {
                    sum += Math.Exp(v - max);
                }
            }

            return max + Math.Log(sum);
        }
    }
}