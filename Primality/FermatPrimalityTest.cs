using System.Numerics;

namespace Primality
{
    /// <summary>
    /// Тест Ферма. Для простого числа n (по малой теореме Ферма):
    /// a^(n-1) = 1 (mod n) для всех a, не делящихся на n
    /// </summary>
    public class FermatPrimalityTest : ProbabilisticPrimalityTestBase
    {
        protected override double PerIterationFailureProbability => 0.5;
        public FermatPrimalityTest(NumberTheory.StatelessNumberTheoryService nt, 
            System.Security.Cryptography.RandomNumberGenerator? rng = null) : base(nt, rng) { }
        protected override bool SingleIteration(BigInteger n)
        {
            // a = 0: 0^(n-1) = 0 mod n - всегда ложно для n > 1
            // a = 1: 1^(n - 1) = 1 mod n - всегда истинно для любого n
            // a = n - 1: (-1)^(n - 1) mod n = +/-1, зависит от четности n-1
            // a >= n: можно взять по модулю n
            var a = RandomInRange(2, n - 2);

            // Вычисление a^(n-1) mod n
            var r = nt.ModPow.ModPow(a, n - 1, n);

            // Если r != 0, то число составное
            return r == 1; 
        }
    }
}