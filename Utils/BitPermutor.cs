using System;

namespace Utils
{
    public static class BitPermutor
    {
        public static byte[] Permute(byte[] input, int[] permutation, bool bitsIndexedLsbFirst = false, 
            bool indexStartsAtOne = true)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (permutation == null) throw new ArgumentNullException(nameof(permutation));
            int outBits = permutation.Length;
            int outBytes = (outBits + 7) / 8;
            var output = new byte[outBytes];

            for (int i = 0; i < outBits; i++)
            {
                int srcIndex = permutation[i] - (indexStartsAtOne ? 1 : 0);
                int srcByte = srcIndex / 8;
                int srcBitInByte = srcIndex % 8;
                int srcBit;
                if (bitsIndexedLsbFirst)
                {
                    srcBit = (input[srcByte] >> srcBitInByte) & 1;
                }
                else
                {
                    srcBit = (input[srcByte] >> (7 - srcBitInByte)) & 1;
                }

                int dstByte = i / 8;
                int dstBitInByte = i % 8;
                output[dstByte] |= (byte)(srcBit << (7 - dstBitInByte));
            }
            return output;
        }

        public static uint RotateLeftBits(uint value, int bitsCount, int rot)
        {
            rot %= bitsCount;
            if (rot == 0) 
                return value & ((1u << bitsCount) - 1u);
            uint mask = (bitsCount == 32) ? 0xFFFFFFFFu : ((1u << bitsCount) - 1u);
            return (((value << rot) | (value >> (bitsCount - rot))) & mask);
        }

        public static uint RotateRightBits(uint value, int bitsCount, int rot)
        {
            rot %= bitsCount;
            if (rot == 0) 
                return value & ((1u << bitsCount) - 1u);
            uint mask = (bitsCount == 32) ? 0xFFFFFFFFu : ((1u << bitsCount) - 1u);
            return (((value >> rot) | (value << (bitsCount - rot))) & mask);
        }
    }
}