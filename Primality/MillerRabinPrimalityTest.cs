using System.Numerics;

namespace Primality
{
    /// <summary>
    /// Тест Миллера-Рабина
    /// </summary>
    public class MillerRabinPrimalityTest : ProbabilisticPrimalityTestBase
    {
        protected override double PerIterationFailureProbability => 0.25;
        public MillerRabinPrimalityTest(NumberTheory.StatelessNumberTheoryService nt, 
            System.Security.Cryptography.RandomNumberGenerator? rng = null) : base(nt, rng) { }

        /// <summary>
        /// Метод разложения.
        /// n-1 = 2^s * d, d - нечётное 
        /// </summary>
        private static void Decompose(BigInteger nMinusOne, out BigInteger d, out int s) 
        { 
            d = nMinusOne; 
            s = 0; 
            while (d.IsEven) 
            { 
                d >>= 1; 
                s++; 
            } 
        }
        protected override bool SingleIteration(BigInteger n)
        {
            Decompose(n - 1, out BigInteger d, out int s);
            var a = RandomInRange(2, n - 2);
            var x = nt.ModPow.ModPow(a, d, n); // х =а^d (mod n)

            // Условия простоты
            if (x == 1 || x == n - 1) 
                return true;


            // Цикл возведения в квадрат
            for (int r = 1; r < s; r++) 
            { 
                x = (x * x) % n; 
                if (x == n - 1) 
                    return true; 
                if (x == 1) 
                    return false; 
            }
            return false;
        }
    }
}