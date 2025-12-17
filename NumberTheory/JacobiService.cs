using System.Numerics;

namespace NumberTheory
{
    // Определён для нечётных n > 0
    // Может быть 1, -1 или 0
    // Если n простое, совпадает с символом Лежандра
    // Если (a/n) = -1, то a — квадратичный невычет по модулю n
    // Если (a/n) = 1, то a может быть как вычетом, так и невычетом (при составном n) 
    public class JacobiService
    {
        /// <summary>
        /// Вычисления значения символа Якоби
        /// </summary>
        public int Jacobi(BigInteger a, BigInteger n)
        {
            if (n <= 0 || n.IsEven) throw new ArgumentException();
            a %= n; 
            if (a < 0) 
                a += n; 
            if (a == 0) 
                return 0; 
            if (a == 1) 
                return 1;
            int result = 1; // будет накапливать знак (+/-1)
            BigInteger A = a, N = n;
            while (A != 0)
            {
                // Шаг 1: Выносим все степени двойки из A
                int t = 0; 
                while (A.IsEven) 
                { 
                    A >>= 1; // Делим A на 2
                    t++; // Считаем, сколько раз поделили
                }

                // Правило для степени двойки:
                if (t != 0) 
                {
                    int nMod8 = (int)(N % 8); 
                    if (nMod8 == 3 || nMod8 == 5) 
                        result = -result; 
                }

                // Шаг 2: Взаимность (квадратичный закон взаимности)
                var tmp = A; 
                A = N; 
                N = tmp;
                if ((A % 4 == 3) && (N % 4 == 3)) result = -result;

                // Шаг 3: Приводим по модулю
                A %= N;
            }
            return N == 1 ? result : 0;
        }
    }
}