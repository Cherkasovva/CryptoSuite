using System.Numerics;

namespace Primality
{
    /// <summary>
    /// Интерфейс для вероятностных тестов простоты
    /// </summary>
    public interface IProbabilisticPrimalityTest
    {
        bool IsProbablyPrime(BigInteger n, double minProbability);
    }
}