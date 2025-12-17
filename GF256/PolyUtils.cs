using System;
using System.Collections.Generic;
using System.Numerics;

namespace GF256
{
    internal static class PolyUtils
    {
        public static int Degree(BigInteger poly)
        {
            if (poly.IsZero) return -1;
            BigInteger v = poly < 0 ? BigInteger.Abs(poly) : poly;
            int deg = 0;
            while (v > 0) 
            { 
                v >>= 1; 
                deg++; 
            }
            return deg - 1;
        }

        public static BigInteger Add(BigInteger a, BigInteger b) => a ^ b;

        public static BigInteger Multiply(BigInteger a, BigInteger b)
        {
            BigInteger result = BigInteger.Zero;
            BigInteger aa = a, bb = b;
            while (bb > 0)
            {
                if (!bb.IsEven) result ^= aa;
                bb >>= 1; aa <<= 1;
            }
            return result;
        }

        public static (BigInteger q, BigInteger r) DivRem(BigInteger a, BigInteger b)
        {
            if (b.IsZero) throw new DivideByZeroException();
            BigInteger A = a, B = b;
            int degA = Degree(A), degB = Degree(B);
            if (degA < degB) 
                return (BigInteger.Zero, A);
            BigInteger Q = BigInteger.Zero, R = A;
            for (int shift = degA - degB; shift >= 0; shift--)
            {
                if (((R >> (degB + shift)) & 1) == 1)
                {
                    Q |= (BigInteger.One << shift);
                    R ^= (B << shift);
                }
            }
            return (Q, R);
        }

        public static BigInteger Mod(BigInteger a, BigInteger b) => DivRem(a, b).r;

        public static BigInteger Gcd(BigInteger a, BigInteger b)
        {
            BigInteger A = a, B = b;
            while (!B.IsZero)
            {
                BigInteger r = Mod(A, B);
                A = B; 
                B = r;
            }
            return A;
        }

        public static BigInteger Square(BigInteger a)
        {
            BigInteger res = BigInteger.Zero;
            BigInteger temp = a;
            int pos = 0;
            while (temp > 0)
            {
                if ((temp & 1) != 0) 
                    res |= (BigInteger.One << (2 * pos));
                temp >>= 1; 
                pos++;
            }
            return res;
        }

        public static BigInteger ModPow(BigInteger @base, BigInteger exp, BigInteger mod)
        {
            BigInteger result = BigInteger.One;
            BigInteger b = @base % mod; 
            if (b < 0) 
                b += mod;
            BigInteger e = exp;
            while (e > 0)
            {
                if (!e.IsEven) result = Mod(Multiply(result, b), mod);
                e >>= 1; b = Mod(Multiply(b, b), mod);
            }
            return Mod(result, mod);
        }

        public static BigInteger ModulusFromByte(byte m) => (BigInteger.One << 8) | new BigInteger(m);
        public static BigInteger FromByte(byte b) => new BigInteger(b);
    }
}