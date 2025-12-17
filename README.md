# CryptoSuite

Aggregated educational cryptography project.

Contents:
- GF(2^8) arithmetic and irreducible polynomial utilities
- DES, TripleDES, DEAL (Feistel-based)
- Rijndael generalized implementation (128/192/256 block/key) with configurable GF modulus
- RC4 (stream cipher) with async file encrypt/decrypt
- Number theory utilities and probabilistic primality tests
- RSA service with nested KeyGenerator and Wiener attack service
- Diffie-Hellman service and demo
- SymmetricCipherContext: modes and padding handling, file helpers

Build & run:
- dotnet build
- dotnet run

Notes:
- This project is for educational/demonstration purposes. Do not use in production without review.