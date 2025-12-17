using Crypto.DES;
using Crypto.Interfaces;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Crypto.DEAL
{
    /// <summary>
    ///  F(R, round) = DES_Encrypt( R XOR вложенный ключ_i , DES_roundKeys_for_subkey_i 
    /// </summary>
    public class DEALCipher : ISymmetricCipher
    {
        // Предварительно рассчитанные ключи раундов DES для каждого раунда раздачи
        // (для каждого раунда раздачи есть свой ключ DES -> 16 ключей раундов DES
        private IReadOnlyList<IReadOnlyList<byte[]>>? desRoundKeysPerDealRound;
        private byte[][]? subKeys;
        private int v;
        private readonly DESAlgorithm desAlg = new DESAlgorithm();
        private readonly DESKeySchedule desKs = new DESKeySchedule();

        public int BlockSizeBytes => 16;

        public DEALCipher()
        {
        }

        public DEALCipher(int v)
        {
            this.v = v;
        }

        /// <summary>
        /// Конфигурация ключей округления
        /// </summary>
        public void ConfigureRoundKeys(byte[] masterKey)
        {
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            subKeys = DEALKeySchedule.GenerateSubKeys(masterKey);

            var list = new List<IReadOnlyList<byte[]>>(16);
            for (int i = 0; i < 16; i++)
            {
                var sub = subKeys[i];
                // Два раундовых ключа
                var rks = desKs.GenerateRoundKeys(sub);
                list.Add(rks);
            }
            desRoundKeysPerDealRound = list.AsReadOnly();
        }

        /// <summary>
        /// Шифрование без сохранения состояния: 
        /// извлечь раундовые ключи из заданного главного ключа и зашифровать один 16-байтовый блок
        /// </summary>
        public byte[] Encrypt(byte[] plaintextBlock, byte[] masterKey)
        {
            if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (plaintextBlock.Length != BlockSizeBytes) throw new ArgumentException($"Plaintext block must be " +
                $"{BlockSizeBytes} bytes.");

            var subs = DEALKeySchedule.GenerateSubKeys(masterKey);
            var rksList = new List<IReadOnlyList<byte[]>>(16);
            for (int i = 0; i < 16; i++) 
                rksList.Add(desKs.GenerateRoundKeys(subs[i]));

            return EncryptBlockWithSchedules(plaintextBlock, subs, rksList);
        }

        /// <summary>
        /// Расшифровка без учета состояния
        /// </summary>
        public byte[] Decrypt(byte[] ciphertextBlock, byte[] masterKey)
        {
            if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (ciphertextBlock.Length != BlockSizeBytes) throw new ArgumentException($"Ciphertext block must be " +
                $"{BlockSizeBytes} bytes.");

            var subs = DEALKeySchedule.GenerateSubKeys(masterKey);
            var rksList = new List<IReadOnlyList<byte[]>>(16);
            for (int i = 0; i < 16; i++) 
                rksList.Add(desKs.GenerateRoundKeys(subs[i]));

            return DecryptBlockWithSchedules(ciphertextBlock, subs, rksList);
        }

        public byte[] EncryptWithConfiguredKeys(byte[] plaintextBlock)
        {
            if (desRoundKeysPerDealRound == null || subKeys == null) throw new InvalidOperationException 
                    ("Round keys not configured.");
            if (plaintextBlock == null) throw new ArgumentNullException(nameof(plaintextBlock));
            if (plaintextBlock.Length != BlockSizeBytes) throw new ArgumentException
                    ($"Plaintext block must be {BlockSizeBytes} bytes.");

            return EncryptBlockWithSchedules(plaintextBlock, subKeys, desRoundKeysPerDealRound);
        }

        public byte[] DecryptWithConfiguredKeys(byte[] ciphertextBlock)
        {
            if (desRoundKeysPerDealRound == null || subKeys == null) throw new InvalidOperationException
                    ("Round keys not configured.");
            if (ciphertextBlock == null) throw new ArgumentNullException(nameof(ciphertextBlock));
            if (ciphertextBlock.Length != BlockSizeBytes) throw new ArgumentException
                    ($"Ciphertext block must be {BlockSizeBytes} bytes.");

            return DecryptBlockWithSchedules(ciphertextBlock, subKeys, desRoundKeysPerDealRound);
        }

        // Шифрование основного блока с использованием предоставленных schedules
        private byte[] EncryptBlockWithSchedules(byte[] plaintextBlock, byte[][] subs, 
            IReadOnlyList<IReadOnlyList<byte[]>> rksList)
        {
            // Разделить на L || R (по 8 байт в каждом)
            var L = new byte[8];
            var R = new byte[8];
            Buffer.BlockCopy(plaintextBlock, 0, L, 0, 8);
            Buffer.BlockCopy(plaintextBlock, 8, R, 0, 8);

            for (int round = 0; round < 16; round++)
            {
                // temp = R XOR subkey[round]
                var temp = new byte[8];
                var sub = subs[round];
                for (int i = 0; i < 8; i++) 
                    temp[i] = (byte)(R[i] ^ sub[i]);

                // F = DES_E(temp, rks_for_round)
                var F = desAlg.EncryptBlock(temp, rksList[round]);

                // newR = L XOR F
                var newR = new byte[8];
                for (int i = 0; i < 8; i++) 
                    newR[i] = (byte)(L[i] ^ F[i]);

                // shift: L <- R, R <- newR
                L = R;
                R = newR;
            }

            // объединение R || L
            var outb = new byte[16];
            Buffer.BlockCopy(R, 0, outb, 0, 8);
            Buffer.BlockCopy(L, 0, outb, 8, 8);
            return outb;
        }

        // Дешифрование основного блока с использованием предоставленных schedules
        private byte[] DecryptBlockWithSchedules(byte[] ciphertextBlock, byte[][] subs, 
            IReadOnlyList<IReadOnlyList<byte[]>> rksList)
        {
            var L = new byte[8];
            var R = new byte[8];
            Buffer.BlockCopy(ciphertextBlock, 0, L, 0, 8);
            Buffer.BlockCopy(ciphertextBlock, 8, R, 0, 8);

            // Запуск раундовых ключей в обратном порядке
            for (int round = 15; round >= 0; round--)
            {
                // F = DES_E(L XOR subkey_round, rks_round)
                var temp = new byte[8];
                var sub = subs[round];
                for (int i = 0; i < 8; i++) 
                    temp[i] = (byte)(L[i] ^ sub[i]);

                var F = desAlg.EncryptBlock(temp, rksList[round]);

                var newL = new byte[8];
                for (int i = 0; i < 8; i++) 
                    newL[i] = (byte)(R[i] ^ F[i]);

                R = L;
                L = newL;
            }

            var outb = new byte[16];
            Buffer.BlockCopy(L, 0, outb, 0, 8);
            Buffer.BlockCopy(R, 0, outb, 8, 8);
            return outb;
        }
    }
}