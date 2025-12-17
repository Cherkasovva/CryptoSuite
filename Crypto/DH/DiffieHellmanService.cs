using System;
using System.Numerics;
using System.Security.Cryptography;
using NumberTheory;

namespace Crypto.DH
{
    public class DiffieHellmanService
    {
        private readonly BigInteger p, g;
        private readonly ModPowService modPow = new ModPowService();
        private readonly RandomNumberGenerator rng;
        public DiffieHellmanService(BigInteger prime, BigInteger generator, RandomNumberGenerator? rng = null) 
        { 
            p = prime; 
            g = generator; 
            this.rng = rng ?? RandomNumberGenerator.Create(); 
        }
        public (BigInteger Private, BigInteger Public) GenerateKeyPair(int privateBitLength = 256)
        {
            BigInteger priv = RandomBigIntegerBelow(p - 3, rng) + 2;
            BigInteger pub = modPow.ModPow(g, priv, p);
            return (priv, pub);
        }
        public BigInteger ComputeSharedSecret(BigInteger privateKey, BigInteger otherPublic) => 
            modPow.ModPow(otherPublic, privateKey, p);
        public static byte[] DeriveAesKey(BigInteger sharedSecret, int keyLenBytes)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            var seed = sharedSecret.ToByteArray(isUnsigned:true,isBigEndian:true);
            var result = new byte[keyLenBytes]; 
            int pos = 0; 
            int ctr = 0;
            while (pos < keyLenBytes)
            {
                var input = new byte[seed.Length + 4]; Buffer.BlockCopy(seed, 0, input, 0, seed.Length);
                input[seed.Length] = (byte)((ctr >> 24)&0xFF); 
                input[seed.Length+1] = (byte)((ctr >> 16)&0xFF); 
                input[seed.Length+2] = (byte)((ctr >>8)&0xFF); 
                input[seed.Length+3] = (byte)(ctr&0xFF);
                var h = sha.ComputeHash(input); 
                int take = Math.Min(h.Length, keyLenBytes - pos); 
                Buffer.BlockCopy(h, 0, result, pos, take); 
                pos += take; ctr++;
            }
            return result;
        }
        private static BigInteger RandomBigIntegerBelow(BigInteger maxExclusive, RandomNumberGenerator rng) 
        { 
            if (maxExclusive <= 0) throw new ArgumentOutOfRangeException(); 
            int bits = GetBitLength(maxExclusive); 
            while (true) { var bytes = new byte[(bits+7)/8]; 
                rng.GetBytes(bytes); var v = new BigInteger(bytes.Concat(new byte[]{0}).ToArray()); 
                if (v < 0) 
                    v = BigInteger.Negate(v); 
                if (v < maxExclusive) 
                    return v; 
            } 
        }
        private static int GetBitLength(BigInteger v) 
        { 
            if (v.IsZero) return 0; 
            BigInteger t = v < 0 ? BigInteger.Negate(v) : v; int c = 0; 
            while (t > 0) 
            { 
                c++; 
                t >>= 1; 
            } 
            return c; 
        }
    }
}