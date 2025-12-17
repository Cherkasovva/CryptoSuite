using System.Numerics;

namespace Primality
{

    /// <summary>
    /// Тест Соловея-Штрассена
    /// </summary>
    public class SolovayStrassenPrimalityTest : ProbabilisticPrimalityTestBase
    {
        protected override double PerIterationFailureProbability => 0.5;
        public SolovayStrassenPrimalityTest(NumberTheory.StatelessNumberTheoryService nt, 
            System.Security.Cryptography.RandomNumberGenerator? rng = null) : base(nt, rng) { }
        protected override bool SingleIteration(BigInteger n)
        {
            var a = RandomInRange(2, n - 1);

            // Если НОД(a, n) > 1, то a и n имеют общий делитель. Значит n точно составное.
            // Можно сразу завершить итерацию с результатом false
            if (BigInteger.GreatestCommonDivisor(a, n) != 1) 
                return false;
            // a^((p-1)/2) = (a/p) mod p
            var x = nt.ModPow.ModPow(a, (n - 1) >> 1, n);
            int jac = nt.Jacobi.Jacobi(a, n);

            // Приведение символа Якоби к модулю n
            BigInteger jacMod = jac == -1 ? n - 1 : (jac == 0 ? BigInteger.Zero : BigInteger.One);
            return x == jacMod;
        }
    }
}