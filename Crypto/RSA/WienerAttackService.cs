using System;
using System.Collections.Generic;
using System.Numerics;

namespace Crypto.RSA
{
    /// <summary>
    /// Атака Винера
    /// </summary>
    public class WienerAttackService
    {
        /// <summary>
        /// Хранилище даннных
        /// </summary>
        /// <param name="ConvergentNumerator">k - числитель подходящей дроби</param>
        /// <param name="ConvergentDenominator"></param>
        /// <param name="CandidateK">k из уравнения</param>
        /// <param name="CandidateD">d-кандидат</param>
        /// <param name="PhiCandidate"></param>
        /// <param name="Validated">прошло ли проверку</param>
        /// <param name="RecoveredP">восстановленный p</param>
        /// <param name="RecoveredQ">восстановленный q</param>
        public record CandidateFraction(BigInteger ConvergentNumerator, BigInteger ConvergentDenominator, 
            BigInteger CandidateK, BigInteger CandidateD, BigInteger? PhiCandidate, bool Validated, 
            BigInteger? RecoveredP, BigInteger? RecoveredQ);

        /// <summary>
        /// Результат атаки
        /// </summary>
        /// <param name="Success">успешна ли атака</param>
        /// <param name="D">найденное d</param>
        /// <param name="Phi">найденное фи</param>
        /// <param name="CandidateFractions">все кандидаты</param>
        public record WienerAttackResult(bool Success, BigInteger? D, BigInteger? Phi, 
            IReadOnlyList<CandidateFraction> CandidateFractions);

        /// <summary>
        /// Атака
        /// </summary>
        /// <param name="e">публичная экспонента</param>
        /// <param name="n">модуль</param>
        /// <returns></returns>
        public WienerAttackResult Attack(BigInteger e, BigInteger n)
        {
            var coeffs = ContinuedFractionCoefficients(e, n);
            // Вычисление коэффициентов непрерывной дроби e/n
            var convergents = ConvergentsFromCoefficients(coeffs);
            // Генерация подходящих дробей из коэффициентов
            var candidates = new List<CandidateFraction>();
            foreach (var (p, q) in convergents)
            {
                if (p == 0) 
                    continue;
                BigInteger k = p, d = q;
                BigInteger edm1 = e * d - 1;
                if (edm1 < 0) 
                    continue;
                if (k == 0) 
                    continue;
                if (edm1 % k != 0) 
                    continue;
                BigInteger phiCandidate = edm1 / k;
                BigInteger s = n - phiCandidate + 1;
                if (s <= 0) 
                { 
                    candidates.Add(new CandidateFraction(p, q, k, d, phiCandidate, false, null, null)); 
                    continue; 
                }
                BigInteger discr = s * s - 4 * n;
                if (discr < 0) 
                { 
                    candidates.Add(new CandidateFraction(p, q, k, d, phiCandidate, false, null, null)); 
                    continue; 
                }
                BigInteger t = IntegerSqrt(discr);
                if (t * t != discr) 
                { 
                    candidates.Add(new CandidateFraction(p, q, k, d, phiCandidate, false, null, null)); 
                    continue; 
                }
                if ((s + t) % 2 != 0) 
                { 
                    candidates.Add(new CandidateFraction(p, q, k, d, phiCandidate, false, null, null)); 
                    continue; 
                }
                BigInteger rp = (s + t) / 2; 
                BigInteger rq = (s - t) / 2;
                if (rp * rq == n && rp > 1 && rq > 1) 
                    return new WienerAttackResult(true, d, phiCandidate, new[] 
                    { 
                        new CandidateFraction(p, q, k, d, phiCandidate, true, rp, rq) });
                candidates.Add(new CandidateFraction(p, q, k, d, phiCandidate, false, rp, rq));
            }
            return new WienerAttackResult(false, null, null, candidates);
        }

        private static List<BigInteger> ContinuedFractionCoefficients(BigInteger numerator, BigInteger denominator)
        {
            var coeffs = new List<BigInteger>();
            BigInteger a = numerator, b = denominator;
            while (b != 0)
            {
                BigInteger q = a / b; coeffs.Add(q); 
                BigInteger r = a % b; a = b; b = r;
            }
            return coeffs;
        }

        private static IEnumerable<(BigInteger p, BigInteger q)> ConvergentsFromCoefficients(List<BigInteger> a)
        {
            BigInteger p2 = 0, p1 = 1, q2 = 1, q1 = 0;
            for (int i = 0; i < a.Count; i++)
            {
                BigInteger ai = a[i]; 
                BigInteger p = ai * p1 + p2; 
                BigInteger q = ai * q1 + q2;
                yield return (p, q);
                p2 = p1; p1 = p; 
                q2 = q1; q1 = q;
            }
        }

        private static BigInteger IntegerSqrt(BigInteger n) 
        { 
            if (n < 0) throw new ArgumentOutOfRangeException(); 
            if (n == 0) 
                return 0; 
            BigInteger x0 = n, x1 = (n >> 1) + 1; 
            while (x1 < x0) 
            { 
                x0 = x1; 
                x1 = (x1 + n / x1) >> 1; 
            } 
            return x0; 
        }
    }
}