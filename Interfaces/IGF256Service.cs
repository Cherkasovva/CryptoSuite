namespace GF256
{
    public interface IGF256Service
    {
        byte Add(byte a, byte b);
        byte Multiply(byte a, byte b, byte modulus);
        byte Inverse(byte a, byte modulus);
        bool IsIrreducibleModulus(byte modulus);
        byte[] GetAllIrreducibleDegree8();
        System.Numerics.BigInteger[] FactorPolynomial(System.Numerics.BigInteger poly);
    }
}