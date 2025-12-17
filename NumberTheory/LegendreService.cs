using System.Numerics;

namespace NumberTheory
{
    
    /// —имвол Ћежандра (a/p) показывает, €вл€етс€ ли число a квадратичным вычетом по модулю простого числа p:
    /// 1 - если a квадратичный вычет (существует x такое, что x^2 = a (mod p))
    /// -1 Ч если a квадратичный невычет
    /// 0 Ч если a кратно p (a = 0 (mod p))
    public class LegendreService
    {
        private readonly ModPowService mp = new ModPowService();

        /// <summary>
        /// ¬ычисление значени€ символа Ћежандра
        /// </summary>
        public int Legendre(BigInteger a, BigInteger p)
        {
            if (p <= 2 || p.IsEven) throw new ArgumentException();
            // ѕриводим a к диапазону [0, p-1]
            a %= p; 
            if (a < 0) 
                a += p; 
            if (a == 0) 
                return 0;
            // »спользуетс€ критерий Ёйлера: (a / p) = a ^ ((p - 1) / 2) (mod p)
            var r = mp.ModPow(a, (p - 1) >> 1, p);
            if (r == 1) 
                return 1; 
            if (r == p - 1) 
                return -1; 
            return 0;
        }
    }
}