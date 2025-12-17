using System;
using System.Collections.Generic;
using System.Numerics;

namespace GF256
{
    public class GF256Service : IGF256Service
    {
        public byte Add(byte a, byte b) => (byte)(a ^ b);

        public byte Multiply(byte a, byte b, byte modulus)
        {
            if (!IsIrreducibleModulus(modulus)) throw new ReducibleModulusException("Modulus reducible.");
            uint aa = a, bb = b;
            uint acc = 0;
            while (bb != 0)
            {
                if ((bb & 1) != 0) 
                    acc ^= aa;
                bb >>= 1; aa <<= 1;
            }
            uint modFull = ((uint)1 << 8) | modulus;
            for (int deg = 15; deg >= 8; deg--)
            {
                if (((acc >> deg) & 1) != 0) 
                    acc ^= (modFull << (deg - 8));
            }
            return (byte)(acc & 0xFF);
        }

        public byte Inverse(byte a, byte modulus)
        {
            if (!IsIrreducibleModulus(modulus)) throw new ReducibleModulusException("Modulus reducible.");
            if (a == 0) throw new InvalidOperationException("Zero inverse.");
            BigInteger modPoly = PolyUtils.ModulusFromByte(modulus);
            BigInteger aPoly = PolyUtils.FromByte(a);
            var (g, s, t) = ExtendedGcdPoly(aPoly, modPoly);
            if (g != BigInteger.One) throw new InvalidOperationException("No inverse.");
            BigInteger inv = PolyUtils.Mod(s, modPoly);
            return (byte)(inv & 0xFF);
        }

        public bool IsIrreducibleModulus(byte modulus)
        {
            BigInteger f = PolyUtils.ModulusFromByte(modulus);
            const int n = 8;
            BigInteger x = BigInteger.One << 1;
            BigInteger v = x;
            for (int i = 1; i <= n / 2; i++)
            {
                v = PolyUtils.Mod(PolyUtils.Square(v), f);
                BigInteger h = PolyUtils.Add(v, x);
                BigInteger g = PolyUtils.Gcd(f, h);
                if (g != BigInteger.One) return false;
            }
            for (int i = 0; i < n / 2; i++) v = PolyUtils.Mod(PolyUtils.Square(v), f);
            return v == x;
        }

        public byte[] GetAllIrreducibleDegree8()
        {
            var list = new List<byte>();
            for (int lower = 0; lower < 256; lower++)
            {
                byte m = (byte)lower;
                try { if (IsIrreducibleModulus(m)) list.Add(m); } catch { }
            }
            return list.ToArray();
        }

        public BigInteger[] FactorPolynomial(BigInteger poly)
        {
            if (poly.IsZero) throw new ArgumentException("Zero poly");
            var remaining = poly;
            var factors = new List<BigInteger>();
            int deg = PolyUtils.Degree(poly);
            for (int d = 1; d <= deg; d++)
            {
                int lowerMax = 1 << d;
                for (int lower = 0; lower < lowerMax; lower++)
                {
                    BigInteger cand = (BigInteger.One << d) | new BigInteger(lower);
                    if (!IsIrreducibleGeneral(cand)) continue;
                    while (true)
                    {
                        var rem = PolyUtils.Mod(remaining, cand);
                        if (!rem.IsZero) break;
                        remaining = PolyUtils.DivRem(remaining, cand).q;
                        factors.Add(cand);
                        if (remaining.IsOne) break;
                    }
                    if (remaining.IsOne) break;
                }
                if (remaining.IsOne) break;
            }
            if (!remaining.IsOne) 
                factors.Add(remaining);
            return factors.ToArray();
        }

        private bool IsIrreducibleGeneral(BigInteger cand)
        {
            int n = PolyUtils.Degree(cand);
            if (n <= 0) return false;
            BigInteger x = BigInteger.One << 1;
            BigInteger v = x;
            for (int i = 1; i <= n / 2; i++)
            {
                v = PolyUtils.Mod(PolyUtils.Square(v), cand);
                BigInteger h = PolyUtils.Add(v, x);
                BigInteger g = PolyUtils.Gcd(cand, h);
                if (g != BigInteger.One) return false;
            }
            for (int i = 0; i < n / 2; i++) 
                v = PolyUtils.Mod(PolyUtils.Square(v), cand);
            return v == x;
        }

        private static (BigInteger g, BigInteger s, BigInteger t) ExtendedGcdPoly(BigInteger a, BigInteger b)
        {
            if (a.IsZero) return (b, BigInteger.Zero, BigInteger.One);
            BigInteger r0 = a, r1 = b;
            BigInteger s0 = BigInteger.One, s1 = BigInteger.Zero;
            BigInteger t0 = BigInteger.Zero, t1 = BigInteger.One;
            while (!r1.IsZero)
            {
                var (q, rem) = PolyUtils.DivRem(r0, r1);
                BigInteger r2 = rem;
                BigInteger s2 = s0 ^ PolyUtils.Multiply(q, s1);
                BigInteger t2 = t0 ^ PolyUtils.Multiply(q, t1);
                r0 = r1; r1 = r2;
                s0 = s1; s1 = s2;
                t0 = t1; t1 = t2;
            }
            return (r0, s0, t0);
        }
    }
}