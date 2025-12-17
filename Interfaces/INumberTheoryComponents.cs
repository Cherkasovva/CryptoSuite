using System.Numerics;

namespace NumberTheory.Interfaces
{
    public interface IGcdService { BigInteger Gcd(BigInteger a, BigInteger b); }
    public interface IExtendedGcdService { (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b); }
    public interface IModPowService { BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus); }
    public interface IJacobiService { int Jacobi(BigInteger a, BigInteger n); }
    public interface ILegendreService { int Legendre(BigInteger a, BigInteger p); }
}