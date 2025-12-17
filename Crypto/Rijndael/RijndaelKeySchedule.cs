using System;
using System.Collections.Generic;
using Crypto.Interfaces;
using GF256;

namespace Crypto.Rijndael
{
    public class RijndaelKeySchedule : IKeySchedule
    {
        private readonly int blockSizeBits;
        private readonly int keySizeBits;
        private readonly IGF256Service gf;
        private readonly byte gfModulus;

        public RijndaelKeySchedule(int blockSizeBits, int keySizeBits, IGF256Service gf, byte gfModulus)
        {
            if (!(blockSizeBits == 128 || blockSizeBits == 192 || blockSizeBits == 256))
                throw new ArgumentOutOfRangeException(nameof(blockSizeBits));
            if (!(keySizeBits == 128 || keySizeBits == 192 || keySizeBits == 256))
                throw new ArgumentOutOfRangeException(nameof(keySizeBits));
            this.blockSizeBits = blockSizeBits;
            this.keySizeBits = keySizeBits;
            this.gf = gf ?? throw new ArgumentNullException(nameof(gf));
            this.gfModulus = gfModulus;
        }

        public IReadOnlyList<byte[]> GenerateRoundKeys(byte[] masterKey)
        {
            int Nk = keySizeBits / 32;
            int Nb = blockSizeBits / 32;
            int Nr = Math.Max(Nb, Nk) + 6;
            int blockBytes = Nb * 4;
            if (masterKey.Length != Nk * 4) throw new ArgumentException($"masterKey length must be {Nk * 4} bytes");
            var roundFunc = new RijndaelRoundFunction(gf, gfModulus);
            int totalWords = Nb * (Nr + 1);
            byte[][] W = new byte[totalWords][];
            for (int i = 0; i < Nk; i++)
            {
                var w = new byte[4];
                Buffer.BlockCopy(masterKey, i * 4, w, 0, 4);
                W[i] = w;
            }
            byte[] Rcon = new byte[1 + (totalWords / Nk) + 2];
            Rcon[1] = 0x01;
            for (int i = 2; i < Rcon.Length; i++) 
                Rcon[i] = gf.Multiply(Rcon[i - 1], 0x02, gfModulus);
            for (int i = Nk; i < totalWords; i++)
            {
                byte[] temp = (byte[])W[i - 1].Clone();
                if (i % Nk == 0)
                {
                    temp = RotWord(temp);
                    for (int j = 0; j < 4; j++) temp[j] = roundFunc.SBoxLookup(temp[j]);
                    int rconIdx = i / Nk;
                    temp[0] ^= Rcon[rconIdx];
                }
                else if (Nk > 6 && (i % Nk) == 4)
                {
                    for (int j = 0; j < 4; j++) temp[j] = roundFunc.SBoxLookup(temp[j]);
                }
                var wPrevNk = W[i - Nk];
                var wOut = new byte[4];
                for (int b = 0; b < 4; b++) 
                    wOut[b] = (byte)(wPrevNk[b] ^ temp[b]);
                W[i] = wOut;
            }
            var roundKeys = new List<byte[]>();
            for (int r = 0; r <= Nr; r++)
            {
                var rk = new byte[blockBytes];
                for (int col = 0; col < Nb; col++) Buffer.BlockCopy(W[r * Nb + col], 0, rk, col * 4, 4);
                roundKeys.Add(rk);
            }
            return roundKeys;
        }

        private static byte[] RotWord(byte[] w) => new byte[] { w[1], w[2], w[3], w[0] };
    }
}