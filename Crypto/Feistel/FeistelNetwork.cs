using System;
using System.Collections.Generic;
using Crypto.Interfaces;

namespace Crypto.Feistel
{
    public class FeistelNetwork : ISymmetricCipher
    {
        private readonly IKeySchedule keySchedule;
        private readonly IRoundFunction roundFunction;
        private readonly int blockSizeBytes;
        private IReadOnlyList<byte[]>? configuredRoundKeys; // предварительно сгенерированные ключи
        public FeistelNetwork(IKeySchedule ks, IRoundFunction rf, int blockSizeBytes)
        {
            keySchedule = ks ?? throw new ArgumentNullException(nameof(ks));
            roundFunction = rf ?? throw new ArgumentNullException(nameof(rf));
            if (blockSizeBytes <= 0 || (blockSizeBytes % 2) != 0) throw new ArgumentOutOfRangeException(nameof(blockSizeBytes));
            // размер блока должен быть чётным, тк Feistel делит блок на 2 равные части
            this.blockSizeBytes = blockSizeBytes;
        }
        public void ConfigureRoundKeys(byte[] key) => configuredRoundKeys = keySchedule.GenerateRoundKeys(key);
        public byte[] Encrypt(byte[] plaintextBlock, byte[] key)
        {
            var rounds = keySchedule.GenerateRoundKeys(key);
            return EncryptWithRoundKeys(plaintextBlock, rounds);
        }
        public byte[] Decrypt(byte[] ciphertextBlock, byte[] key)
        {
            var rounds = keySchedule.GenerateRoundKeys(key);
            return DecryptWithRoundKeys(ciphertextBlock, rounds);
        }
        public byte[] EncryptWithConfiguredKeys(byte[] plaintextBlock)
        {
            if (configuredRoundKeys == null) throw new InvalidOperationException();
            return EncryptWithRoundKeys(plaintextBlock, configuredRoundKeys);
        }
        public byte[] DecryptWithConfiguredKeys(byte[] ciphertextBlock)
        {
            if (configuredRoundKeys == null) throw new InvalidOperationException();
            return DecryptWithRoundKeys(ciphertextBlock, configuredRoundKeys);
        }

        /// <summary>
        /// Для раунда i:
        /// L_{i+1} = R_i
        /// R_{i+1} = L_i xor F(R_i, K_i)
        /// </summary>
        private byte[] EncryptWithRoundKeys(byte[] block, IReadOnlyList<byte[]> roundKeys)
        {
            // делим блок на 2 части
            int half = blockSizeBytes / 2;
            var L = new byte[half];
            var R = new byte[half];
            Buffer.BlockCopy(block, 0, L, 0, half);
            Buffer.BlockCopy(block, half, R, 0, half);

            // проходим все раундовые ключи
            for (int i = 0; i < roundKeys.Count; i++)
            {
                // используется R
                var F = roundFunction.Transform(R, roundKeys[i]);
                // XOR L и F -> newR
                var newR = new byte[half];
                for (int j = 0; j < half; j++) 
                    newR[j] = (byte)(L[j] ^ F[j]);

                // Сдвиг: L <- R, R <- newR
                var Lnext = new byte[half];
                Buffer.BlockCopy(R, 0, Lnext, 0, half);
                L = Lnext;
                R = newR;
            }
            var outb = new byte[blockSizeBytes];
            Buffer.BlockCopy(R, 0, outb, 0, half);
            Buffer.BlockCopy(L, 0, outb, half, half);
            return outb;
        }

        /// <summary>
        /// R_i = L_{i+1}
        /// L_i = R_{i+1} xor F(R_i, K_i)
        /// </summary>
        private byte[] DecryptWithRoundKeys(byte[] block, IReadOnlyList<byte[]> roundKeys)
        {
            int half = blockSizeBytes / 2;
            var L = new byte[half];
            var R = new byte[half];
            Buffer.BlockCopy(block, 0, L, 0, half);
            Buffer.BlockCopy(block, half, R, 0, half);

            // идём в обратном порядке
            for (int idx = roundKeys.Count - 1; idx >= 0; idx--)
            {
                // используется L
                var F = roundFunction.Transform(L, roundKeys[idx]);
                var newL = new byte[half];
                for (int j = 0; j < half; j++) 
                    newL[j] = (byte)(R[j] ^ F[j]);

                var Rnext = new byte[half];
                Buffer.BlockCopy(L, 0, Rnext, 0, half);
                R = Rnext;
                L = newL;
            }
            var outb = new byte[blockSizeBytes];
            Buffer.BlockCopy(L, 0, outb, 0, half);
            Buffer.BlockCopy(R, 0, outb, half, half);
            return outb;
        }
    }
}