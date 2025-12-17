using System;
using System.Threading;
using GF256;

namespace Crypto.Rijndael
{
    public class RijndaelRoundFunction
    {
        private readonly IGF256Service gf;
        private readonly byte gfModulus;
        private readonly byte[] sBox = new byte[256];
        private readonly byte[] invSBox = new byte[256];
        private int initialized = 0;
        private readonly object initLock = new object();

        public RijndaelRoundFunction(IGF256Service gf, byte gfModulus)
        {
            this.gf = gf ?? throw new ArgumentNullException(nameof(gf));
            this.gfModulus = gfModulus;
        }

        public byte SBoxLookup(byte val) { EnsureInitialized(); return sBox[val]; }
        public byte InvSBoxLookup(byte val) { EnsureInitialized(); return invSBox[val]; }

        private void EnsureInitialized()
        {
            if (Volatile.Read(ref initialized) == 2) return;

            bool doInit = false;
            if (Interlocked.CompareExchange(ref initialized, 1, 0) == 0)
            {
                doInit = true;
            }
            else
            {
                while (Volatile.Read(ref initialized) != 2)
                {
                    Thread.SpinWait(1);
                }
            }

            if (doInit)
            {
                try
                {
                    InitializeBoxes();
                }
                finally
                {
                    Volatile.Write(ref initialized, 2);
                }
            }
        }

        private void InitializeBoxes()
        {
            byte[] affine = new byte[256];
            byte[] inverseAffine = new byte[256];

            for (int a = 0; a < 256; a++)
            {
                byte ba = (byte)a;
                byte t = (byte)(ba ^ RotL(ba, 1) ^ RotL(ba, 2) ^ RotL(ba, 3) ^ RotL(ba, 4) ^ 0x63);
                affine[a] = t;
            }

            for (int i = 0; i < 256; i++) inverseAffine[i] = 0;
            for (int a = 0; a < 256; a++)
            {
                inverseAffine[affine[a]] = (byte)a;
            }

            for (int x = 0; x < 256; x++)
            {
                byte bx = (byte)x;
                byte pre;
                if (bx == 0) 
                    pre = 0;
                else pre = gf.Inverse(bx, gfModulus);
                sBox[x] = affine[pre];
            }


            for (int y = 0; y < 256; y++)
            {
                byte a = inverseAffine[y]; 
                byte res;
                if (a == 0) 
                    res = 0;
                else res = gf.Inverse(a, gfModulus);
                invSBox[y] = res;
            }
        }

        private static byte RotL(byte v, int shift)
        {
            shift &= 7;
            return (byte)(((v << shift) | (v >> (8 - shift))) & 0xFF);
        }
    }
}