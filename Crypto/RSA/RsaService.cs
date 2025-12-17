using System;
using System.Numerics;
using System.Security.Cryptography;
using NumberTheory;

namespace Crypto.RSA
{
    public partial class RsaService
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="N">модуль (public): n = p * q</param>
        /// <param name="E">публичная экспонента</param>
        /// <param name="D">приватная экспонента (d = e^(-1) mod фи(n))</param>
        /// <param name="P">первый простой множитель</param>
        /// <param name="Q">второй простой множитель</param>
        public record RsaKeyPair(BigInteger N, BigInteger E, BigInteger D, BigInteger P, BigInteger Q);
        public enum PrimalityTestType { Fermat, SolovayStrassen, MillerRabin }
        public class KeyGenerator
        {
            private readonly PrimalityTestType testType;
            private readonly double minProbability;
            private readonly int primeBitLength;
            private readonly RandomNumberGenerator rng;
            public KeyGenerator(PrimalityTestType testType, double minProbability,
                int primeBitLength, RandomNumberGenerator? rng = null)
            {
                this.testType = testType;
                this.minProbability = minProbability;
                this.primeBitLength = primeBitLength; // длина простых чисел в битах
                this.rng = rng ?? RandomNumberGenerator.Create();
            }
            /// <summary>
            /// Создание теста простоты
            /// </summary>
            /// <returns></returns>
            private Primality.IProbabilisticPrimalityTest CreatePrimalityTester()
            {
                var nt = new NumberTheory.StatelessNumberTheoryService();
                return testType switch
                {
                    PrimalityTestType.Fermat => new Primality.FermatPrimalityTest(nt, rng),
                    PrimalityTestType.SolovayStrassen => new Primality.SolovayStrassenPrimalityTest(nt, rng),
                    _ => new Primality.MillerRabinPrimalityTest(nt, rng)
                };
            }
            public RsaKeyPair GenerateKeyPair(BigInteger? publicExponent = null)
            {
                var e = publicExponent ?? 65537;
                var tester = CreatePrimalityTester();
                while (true)
                {
                    var p = GeneratePrime(primeBitLength, tester);
                    BigInteger q;
                    do
                    {
                        q = GeneratePrime(primeBitLength, tester);
                    }
                    while (q == p);

                    BigInteger n = p * q;
                    // Функция Эйлера
                    BigInteger phi = (p - 1) * (q - 1);

                    // Проверка взаимной простоты e и фи 
                    var ext = new ExtendedGcdService().ExtendedGcd(e, phi);
                    var g = BigInteger.Abs(ext.gcd);
                    if (g != 1)
                        continue;
                    BigInteger d = ext.x % phi;
                    if (d < 0)
                        d += phi;

                    // Криптографические проверки безопасности
                    // Вычисляется корень 4 степени из n
                    BigInteger nQuarter = IntegerRoot(n, 4);
                    if (d <= nQuarter) // Защита от атаки Винера
                        continue;

                    // Простые числа p и q не должны быть слишком близкими
                    BigInteger diff = BigInteger.Abs(p - q);
                    if (diff < (BigInteger)1 << 16)
                        continue;

                    // Все проверки пройдены
                    return new RsaKeyPair(n, e, d, p, q);
                }
            }
            /// <summary>
            /// Метод генерации простых чисел
            /// </summary>
            private BigInteger GeneratePrime(int bits, Primality.IProbabilisticPrimalityTest tester)
            {
                int bytes = (bits + 7) / 8;
                var buf = new byte[bytes];
                while (true) // пока не найдём простое число
                {
                    rng.GetBytes(buf);
                    buf[buf.Length - 1] |= (byte)(1 << ((bits - 1) % 8));
                    // |= 0x80 устанавливает старший бит последнего байта
                    buf[0] |= 1;
                    var candidate = new BigInteger(buf.Concat(new byte[] { 0 }).ToArray());
                    if (candidate < 0)
                        candidate = BigInteger.Negate(candidate);
                    if (tester.IsProbablyPrime(candidate, minProbability))
                        return candidate;
                }
            }
            /// <summary>
            /// Метод вычисления корня k-й степени
            /// </summary>
            private static BigInteger IntegerRoot(BigInteger value, int k)
            {
                if (k < 1) throw new ArgumentOutOfRangeException();
                if (value < 0) throw new ArgumentOutOfRangeException();
                if (value == 0)
                    return 0;
                BigInteger low = 0;           // Минимум
                BigInteger high = value;      // Максимум (корень =< value)
                while (low <= high)
                {
                    BigInteger mid = (low + high) >> 1; // Вычисление середины
                    var pow = BigInteger.Pow(mid, k);
                    int cmp = pow.CompareTo(value);
                    if (cmp == 0)
                        return mid; // Нашли точный корень!
                    if (cmp < 0)
                        low = mid + 1; // mid^2 меньше исходное числа, то увеличиваем low
                    else
                        high = mid - 1;
                }
                return low - 1;
            }
        }

        protected readonly ModPowService modPow = new ModPowService();
        public byte[] Encrypt(RsaKeyPair key, byte[] data) => throw new NotImplementedException("One-shot RSA not used in demo; use file methods in partial.");
        public byte[] Decrypt(RsaKeyPair key, byte[] data) => throw new NotImplementedException("One-shot RSA not used in demo; use file methods in partial.");
    }
}