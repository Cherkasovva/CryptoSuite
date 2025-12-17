using Crypto.DH;
using Crypto.Rijndael;
using GF256;
using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Examples
{
    class ProgramDHDemo
    {
        public static async Task RunDemo()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.WriteLine("Diffie-Hellman demo");

            var nt = new NumberTheory.StatelessNumberTheoryService();
            var mr = new Primality.MillerRabinPrimalityTest(nt, RandomNumberGenerator.Create());

            BigInteger p;
            var rng = RandomNumberGenerator.Create();
            int bits = 512;
            while (true)
            {
                byte[] buf = new byte[(bits + 7) / 8];
                rng.GetBytes(buf);
                buf[buf.Length - 1] |= (byte)(1 << ((bits - 1) % 8));
                buf[0] |= 1;
                p = new BigInteger(buf.Concat(new byte[] { 0 }).ToArray());
                if (p < 0) p = BigInteger.Negate(p);
                if (mr.IsProbablyPrime(p, 0.999)) break;
            }

            var dh = new DiffieHellmanService(p, new BigInteger(2), rng);
            var (aPriv, aPub) = dh.GenerateKeyPair();
            var (bPriv, bPub) = dh.GenerateKeyPair();
            var aShared = dh.ComputeSharedSecret(aPriv, bPub);
            var bShared = dh.ComputeSharedSecret(bPriv, aPub);
            Console.WriteLine($"Shared equal: {aShared == bShared}");

            var keyBytes = DiffieHellmanService.DeriveAesKey(aShared, 16);
            IGF256Service gf = new GF256Service();
            var rij = new RijndaelCipher(128, 128, gf, 0x1B);
            rij.ConfigureRoundKeys(keyBytes);
            var ctx = new Crypto.Context.SymmetricCipherContext(rij, keyBytes, Crypto.Enums.CipherModeEnum.CBC, Crypto.Enums.PaddingModeEnum.PKCS7, blockSizeBytes: 16);
            byte[] data = new byte[1024]; rng.GetBytes(data);
            var enc = await ctx.EncryptAsync(data);
            var dec = await ctx.DecryptAsync(enc);
            Console.WriteLine($"Roundtrip equal: {dec.SequenceEqual(data)}");
        }
    }
}