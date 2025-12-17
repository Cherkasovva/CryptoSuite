using System;
using System.Collections.Generic;
using Crypto.Interfaces;
using GF256;

namespace Crypto.Rijndael
{
    // RijndaelCipher теперь реализует интерфейс ISymmetricCipher
    public class RijndaelCipher : ISymmetricCipher
    {
        private readonly int blockSizeBits;
        private readonly int keySizeBits;
        private readonly IGF256Service gf;
        private readonly byte gfModulus;
        private readonly RijndaelKeySchedule keySchedule;
        private readonly RijndaelRoundFunction roundFunction;
        private IReadOnlyList<byte[]>? configuredRoundKeys;

        public RijndaelCipher(int blockSizeBits, int keySizeBits, IGF256Service gf, byte gfModulus)
        {
            if (!(blockSizeBits == 128 || blockSizeBits == 192 || blockSizeBits == 256))
                throw new ArgumentOutOfRangeException(nameof(blockSizeBits));
            if (!(keySizeBits == 128 || keySizeBits == 192 || keySizeBits == 256))
                throw new ArgumentOutOfRangeException(nameof(keySizeBits));
            this.blockSizeBits = blockSizeBits;
            this.keySizeBits = keySizeBits;
            this.gf = gf ?? throw new ArgumentNullException(nameof(gf));
            this.gfModulus = gfModulus;
            keySchedule = new RijndaelKeySchedule(blockSizeBits, keySizeBits, gf, gfModulus);
            roundFunction = new RijndaelRoundFunction(gf, gfModulus);
        }

        public void ConfigureRoundKeys(byte[] key)
        {
            configuredRoundKeys = keySchedule.GenerateRoundKeys(key);
        }

        public byte[] Encrypt(byte[] plaintextBlock, byte[] key)
        {
            if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
            if (key == null) throw new ArgumentNullException(nameof(key));
            var roundKeys = keySchedule.GenerateRoundKeys(key);
            return EncryptWithRoundKeys(plaintextBlock, roundKeys);
        }

        public byte[] Decrypt(byte[] ciphertextBlock, byte[] key)
        {
            if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
            if (key == null) throw new ArgumentNullException(nameof(key));
            var roundKeys = keySchedule.GenerateRoundKeys(key);
            return DecryptWithRoundKeys(ciphertextBlock, roundKeys);
        }

        public byte[] EncryptWithConfiguredKeys(byte[] plaintextBlock)
        {
            if (configuredRoundKeys == null) throw new InvalidOperationException("Round keys not configured.");
            return EncryptWithRoundKeys(plaintextBlock, configuredRoundKeys);
        }

        public byte[] DecryptWithConfiguredKeys(byte[] ciphertextBlock)
        {
            if (configuredRoundKeys == null) throw new InvalidOperationException("Round keys not configured.");
            return DecryptWithRoundKeys(ciphertextBlock, configuredRoundKeys);
        }

        private byte[] EncryptWithRoundKeys(byte[] stateBlock, IReadOnlyList<byte[]> roundKeys)
        {
            int Nb = blockSizeBits / 32;
            int Nr = roundKeys.Count - 1;
            int blockBytes = blockSizeBits / 8;

            byte[,] state = new byte[4, Nb];
            for (int c = 0; c < Nb; c++)
                for (int r = 0; r < 4; r++)
                    state[r, c] = stateBlock[c * 4 + r];

            AddRoundKeyInPlace(state, roundKeys[0], Nb);

            for (int round = 1; round < Nr; round++)
            {
                SubBytesInPlace(state, Nb);
                ShiftRowsInPlace(state, Nb);
                MixColumnsInPlace(state, Nb);
                AddRoundKeyInPlace(state, roundKeys[round], Nb);
            }

            SubBytesInPlace(state, Nb);
            ShiftRowsInPlace(state, Nb);
            AddRoundKeyInPlace(state, roundKeys[Nr], Nb);

            var outb = new byte[blockBytes];
            for (int c = 0; c < Nb; c++)
                for (int r = 0; r < 4; r++)
                    outb[c * 4 + r] = state[r, c];

            return outb;
        }

        private byte[] DecryptWithRoundKeys(byte[] stateBlock, IReadOnlyList<byte[]> roundKeys)
        {
            int Nb = blockSizeBits / 32;
            int Nr = roundKeys.Count - 1;
            int blockBytes = blockSizeBits / 8;

            byte[,] state = new byte[4, Nb];
            for (int c = 0; c < Nb; c++)
                for (int r = 0; r < 4; r++)
                    state[r, c] = stateBlock[c * 4 + r];


            AddRoundKeyInPlace(state, roundKeys[Nr], Nb);
            InvShiftRowsInPlace(state, Nb);
            InvSubBytesInPlace(state, Nb);

            for (int round = Nr - 1; round >= 1; round--)
            {
                AddRoundKeyInPlace(state, roundKeys[round], Nb);
                InvMixColumnsInPlace(state, Nb);
                InvShiftRowsInPlace(state, Nb);
                InvSubBytesInPlace(state, Nb);
            }

            AddRoundKeyInPlace(state, roundKeys[0], Nb);

            var outb = new byte[blockBytes];
            for (int c = 0; c < Nb; c++)
                for (int r = 0; r < 4; r++)
                    outb[c * 4 + r] = state[r, c];

            return outb;
        }

        #region primitives

        private void SubBytesInPlace(byte[,] state, int Nb)
        {
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < Nb; c++)
                    state[r, c] = roundFunction.SBoxLookup(state[r, c]);
        }

        private void InvSubBytesInPlace(byte[,] state, int Nb)
        {
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < Nb; c++)
                    state[r, c] = roundFunction.InvSBoxLookup(state[r, c]);
        }

        private void ShiftRowsInPlace(byte[,] state, int Nb)
        {
            var tmp = new byte[Math.Max(8, Nb)];
            for (int r = 1; r < 4; r++)
            {
                for (int c = 0; c < Nb; c++) tmp[c] = state[r, (c + r) % Nb];
                for (int c = 0; c < Nb; c++) state[r, c] = tmp[c];
            }
        }

        private void InvShiftRowsInPlace(byte[,] state, int Nb)
        {
            var tmp = new byte[Math.Max(8, Nb)];
            for (int r = 1; r < 4; r++)
            {
                for (int c = 0; c < Nb; c++) tmp[c] = state[r, (c - r + Nb) % Nb];
                for (int c = 0; c < Nb; c++) state[r, c] = tmp[c];
            }
        }

        private void MixColumnsInPlace(byte[,] state, int Nb)
        {
            for (int c = 0; c < Nb; c++)
            {
                byte a0 = state[0, c];
                byte a1 = state[1, c];
                byte a2 = state[2, c];
                byte a3 = state[3, c];

                byte new0 = (byte)(gf.Multiply(0x02, a0, gfModulus) ^ gf.Multiply(0x03, a1, gfModulus) ^ a2 ^ a3);
                byte new1 = (byte)(a0 ^ gf.Multiply(0x02, a1, gfModulus) ^ gf.Multiply(0x03, a2, gfModulus) ^ a3);
                byte new2 = (byte)(a0 ^ a1 ^ gf.Multiply(0x02, a2, gfModulus) ^ gf.Multiply(0x03, a3, gfModulus));
                byte new3 = (byte)(gf.Multiply(0x03, a0, gfModulus) ^ a1 ^ a2 ^ gf.Multiply(0x02, a3, gfModulus));

                state[0, c] = new0;
                state[1, c] = new1;
                state[2, c] = new2;
                state[3, c] = new3;
            }
        }

        private void InvMixColumnsInPlace(byte[,] state, int Nb)
        {
            for (int c = 0; c < Nb; c++)
            {
                byte a0 = state[0, c];
                byte a1 = state[1, c];
                byte a2 = state[2, c];
                byte a3 = state[3, c];

                byte new0 = (byte)(gf.Multiply(0x0e, a0, gfModulus) ^ gf.Multiply(0x0b, a1, gfModulus) ^ gf.Multiply(0x0d, a2, gfModulus) ^ gf.Multiply(0x09, a3, gfModulus));
                byte new1 = (byte)(gf.Multiply(0x09, a0, gfModulus) ^ gf.Multiply(0x0e, a1, gfModulus) ^ gf.Multiply(0x0b, a2, gfModulus) ^ gf.Multiply(0x0d, a3, gfModulus));
                byte new2 = (byte)(gf.Multiply(0x0d, a0, gfModulus) ^ gf.Multiply(0x09, a1, gfModulus) ^ gf.Multiply(0x0e, a2, gfModulus) ^ gf.Multiply(0x0b, a3, gfModulus));
                byte new3 = (byte)(gf.Multiply(0x0b, a0, gfModulus) ^ gf.Multiply(0x0d, a1, gfModulus) ^ gf.Multiply(0x09, a2, gfModulus) ^ gf.Multiply(0x0e, a3, gfModulus));

                state[0, c] = new0;
                state[1, c] = new1;
                state[2, c] = new2;
                state[3, c] = new3;
            }
        }

        private void AddRoundKeyInPlace(byte[,] state, byte[] roundKey, int Nb)
        {
            for (int c = 0; c < Nb; c++)
                for (int r = 0; r < 4; r++)
                    state[r, c] = (byte)(state[r, c] ^ roundKey[c * 4 + r]);
        }

        #endregion
    }
}