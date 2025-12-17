using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Primality
{
    /// <summary>
    ///  ласс дл€ веро€тностных тестов простоты
    /// </summary>
    public abstract class ProbabilisticPrimalityTestBase : IProbabilisticPrimalityTest
    {
        // —ервис дл€ теоретико-числовых операций
        protected readonly NumberTheory.StatelessNumberTheoryService nt;

        // √енератор криптографически безопасных случайных чисел
        protected readonly RandomNumberGenerator rng;

        // ¬еро€тность ошибки за итерацию
        protected abstract double PerIterationFailureProbability { get; }
        protected ProbabilisticPrimalityTestBase(NumberTheory.StatelessNumberTheoryService nt, 
            RandomNumberGenerator? rng = null) 
        { 
            this.nt = nt; 
            this.rng = rng ?? RandomNumberGenerator.Create();
            // ?? - оператор null-coalescing, использует rng если не null, иначе создает новый
        }
        /// <summary>
        /// ћетод проверки числа на простоту с веро€тностным алгоритмом
        /// </summary>
        public bool IsProbablyPrime(BigInteger n, // число дл€ проверки
            double minProbability) // минимальна€ требуема€ веро€тность того, что число простое
        {
            if (minProbability < 0.5 || minProbability >= 1.0) throw new ArgumentOutOfRangeException();
            if (n < 2) 
                return false; 
            if (n == 2 || n == 3) 
                return true; 
            if (n.IsEven) 
                return false;
            int[] sp = new[] {3,5,7,11,13,17,19,23,29,31}; // первые простые числа до 31

            // ѕроверка делимости на малые простые
            foreach (var p in sp) 
            { 
                if (n == p)
                    return true; 
                if (n % p == 0)
                    return false; 
            }

            // –асчет необходимого количества итераций
            double f = PerIterationFailureProbability; 
            double target = 1 - minProbability; // ƒопустима€ веро€тность ошибки
            int k = (int)Math.Ceiling(Math.Log(target) / Math.Log(f)); if (k < 1) k = 1;
            for (int i = 0; i < k; i++)
            {
                if (!SingleIteration(n)) //  ажда€ неудачна€ итераци€ доказывает, что число составное
                    return false;
            }
            return true;
        }
        /// <summary>
        /// ћетод дл€ одной итерации.
        /// ¬озвращает true, если тест "не нашел" свидетельство составности.
        /// ¬озвращает false, если точно нашел, что число составное.
        /// </summary>
        protected abstract bool SingleIteration(BigInteger n);

        /// <summary>
        /// ћетод дл€ генерации случайных чисел
        /// </summary>
        protected BigInteger RandomInRange(BigInteger minInclusive, BigInteger maxInclusive)
        {
            if (minInclusive > maxInclusive) throw new ArgumentException();
            if (minInclusive == maxInclusive) 
                return minInclusive;

            // ¬ычисл€ет диапазон
            BigInteger range = maxInclusive - minInclusive + 1;
            var r = RandomBigInteger.GetRandomBigIntegerBelow(range, rng);
            return minInclusive + r; // чтобы получилось нужно число
        }
    }
}