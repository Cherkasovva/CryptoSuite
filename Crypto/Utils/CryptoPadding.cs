using Crypto.Enums;
using System;
using System.Security.Cryptography;

namespace Crypto.Utils
{
    /// <summary>
    /// Режимы набивки
    /// Если исходные данные не кратны размеру блока, то нужно дополнить их до нужного размера
    /// </summary>
    internal static class CryptoPadding
    {
        /// <summary>
        /// Добавление набивки
        /// </summary>
        public static byte[] ApplyPadding(byte[] data, int blockSize, PaddingModeEnum padding)
        {
            if (blockSize <= 0) throw new ArgumentOutOfRangeException(nameof(blockSize));
            if (data is null) throw new ArgumentNullException(nameof(data));

            // расчёт размера дополнения
            int padLen = blockSize - (data.Length % blockSize);
            if (padLen == 0 && padding == PaddingModeEnum.Zeros) return (byte[])data.Clone();
            // при Zeros исходные данные уже кратны размеру блока

            switch (padding)
            {
                case PaddingModeEnum.Zeros:
                    {
                        var outz = new byte[data.Length + padLen];
                        Buffer.BlockCopy(data, 0, outz, 0, data.Length);
                        return outz;
                    }
                case PaddingModeEnum.ANSIX923:
                    {
                        var outa = new byte[data.Length + padLen];
                        Buffer.BlockCopy(data, 0, outa, 0, data.Length);
                        outa[outa.Length - 1] = (byte)padLen; // последний байт содержит количество добавленных байтов
                        return outa;
                    }
                case PaddingModeEnum.PKCS7:
                    {
                        var outp = new byte[data.Length + padLen];
                        Buffer.BlockCopy(data, 0, outp, 0, data.Length);
                        for (int i = data.Length; i < outp.Length; i++) 
                            outp[i] = (byte)padLen;
                        // все байты набивки равны значению padLen
                        return outp;
                    }
                case PaddingModeEnum.ISO10126:
                    {
                        var outi = new byte[data.Length + padLen];
                        Buffer.BlockCopy(data, 0, outi, 0, data.Length);
                        using (var rng = RandomNumberGenerator.Create())
                        {
                            if (padLen - 1 > 0) // (padLen - 1) случайных байтов
                            {
                                var rnd = new byte[padLen - 1];
                                rng.GetBytes(rnd);
                                Buffer.BlockCopy(rnd, 0, outi, data.Length, rnd.Length);
                            }
                        }
                        outi[outi.Length - 1] = (byte)padLen;
                        // последний байт равен padLen
                        return outi;
                    }
                default:
                    throw new ArgumentOutOfRangeException(nameof(padding));
            }
        }

        /// <summary>
        /// Удаление набивки
        /// </summary>
        public static byte[] RemovePadding(byte[] data, int blockSize, PaddingModeEnum padding)
        {
            if (blockSize <= 0) throw new ArgumentOutOfRangeException(nameof(blockSize));
            if (data is null) throw new ArgumentNullException(nameof(data));
            if (data.Length == 0) return Array.Empty<byte>();

            switch (padding)
            {
                case PaddingModeEnum.Zeros:
                    {
                        int i = data.Length - 1; // идём с конца
                        while (i >= 0 && data[i] == 0) i--; // находим последний ненулевой элемент
                        var outz = new byte[i + 1];
                        if (outz.Length > 0) Buffer.BlockCopy(data, 0, outz, 0, outz.Length);
                        // копируем всё до этого последнего ненулевого элемента
                        return outz;
                    }

                case PaddingModeEnum.ANSIX923:
                    {
                        byte padB = data[data.Length - 1]; // последний байт
                        int pad = padB; // длина набивки
                        if (pad < 1 || pad > blockSize || pad > data.Length)
                            throw new CryptographicException("Invalid ANSI X9.23 padding (length byte invalid).");

                        // все байты, кроме последнего, нули
                        int start = data.Length - pad;
                        for (int i = start; i < data.Length - 1; i++)
                        {
                            if (data[i] != 0)
                                throw new CryptographicException("Invalid ANSI X9.23 padding (non-zero fill bytes).");
                        }

                        int outLen = data.Length - pad; 
                        if (outLen <= 0) return Array.Empty<byte>();
                        var outa = new byte[outLen];
                        Buffer.BlockCopy(data, 0, outa, 0, outLen);
                        return outa;
                    }

                case PaddingModeEnum.PKCS7:
                    {
                        byte padB = data[data.Length - 1];
                        int pad = padB;

                        if (pad < 1 || pad > blockSize || pad > data.Length)
                        {
                            Console.WriteLine($"PKCS7 Error - pad: {pad}, blockSize: {blockSize}");
                            throw new CryptographicException("Invalid PKCS7 padding (length byte invalid).");
                        }

                        // все байты набивки одинаковы
                        for (int i = data.Length - pad; i < data.Length; i++)
                        {
                            if (data[i] != padB)
                                throw new CryptographicException("Invalid PKCS7 padding (mismatched padding bytes).");
                        }

                        int outLen = data.Length - pad;
                        if (outLen <= 0) return Array.Empty<byte>();
                        var outp = new byte[outLen];
                        Buffer.BlockCopy(data, 0, outp, 0, outLen);
                        return outp;
                    }

                case PaddingModeEnum.ISO10126:
                    {
                        byte padB = data[data.Length - 1];
                        int pad = padB;
                        if (pad < 1 || pad > blockSize || pad > data.Length)
                            throw new CryptographicException("Invalid ISO10126 padding (length byte invalid).");

                        int outLen = data.Length - pad; 
                        if (outLen <= 0) return Array.Empty<byte>();
                        var outi = new byte[outLen];
                        Buffer.BlockCopy(data, 0, outi, 0, outLen);
                        return outi;
                    }

                default:
                    throw new ArgumentOutOfRangeException(nameof(padding));
            }
        }
    }
}