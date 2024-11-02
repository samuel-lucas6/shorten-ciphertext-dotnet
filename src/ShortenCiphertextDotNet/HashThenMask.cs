using System.Security.Cryptography;
using Geralt;

namespace ShortenCiphertextDotNet;

// AES with Davies-Meyer can be replaced with a collision-resistant hash function
// However, AES is more performant (with hardware support)
public static class HashThenMask
{
    public const int MaskedPlaintextSize = BlockSize;
    public const int MinTagSize = 4; // 32 bits
    public const int MaxTagSize = MaxInputSize;
    public const int PlaintextSize = MaxInputSize;
    public const int KeySize = 32; // 256 bits
    private const int BlockSize = 16; // 128 bits
    private const int MaxInputSize = BlockSize - 1; // 120 bits

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key)
    {
        Validation.SizeBetween(nameof(ciphertext), ciphertext.Length, BlockSize + MinTagSize, BlockSize + MaxTagSize);
        Validation.NotGreaterThanMax(nameof(plaintext), plaintext.Length, PlaintextSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> maskedPlaintext = ciphertext[..BlockSize];
        Span<byte> tag = ciphertext[BlockSize..];

        using var aes = Aes.Create();
        aes.Key = key.ToArray();

        Span<byte> paddedPlaintext = stackalloc byte[BlockSize];
        Pad(paddedPlaintext, plaintext, 0);
        // Using maskedPlaintext to avoid an allocation
        aes.EncryptEcb(paddedPlaintext, maskedPlaintext, PaddingMode.None);
        // Davies-Meyer
        XorBytes(maskedPlaintext, paddedPlaintext);
        // Truncate the output
        maskedPlaintext[..tag.Length].CopyTo(tag);

        Span<byte> paddedTag = stackalloc byte[BlockSize];
        Pad(paddedTag, tag, 1);
        aes.EncryptEcb(paddedTag, maskedPlaintext, PaddingMode.None);
        // Davies-Meyer
        XorBytes(maskedPlaintext, paddedTag);
        // Mask paddedPlaintext
        XorBytes(maskedPlaintext, paddedPlaintext);

        CryptographicOperations.ZeroMemory(paddedPlaintext);
        CryptographicOperations.ZeroMemory(paddedTag);
    }

    public static int Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key)
    {
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, PlaintextSize);
        Validation.SizeBetween(nameof(ciphertext), ciphertext.Length, BlockSize + MinTagSize, BlockSize + MaxTagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        ReadOnlySpan<byte> maskedPlaintext = ciphertext[..BlockSize];
        ReadOnlySpan<byte> tag = ciphertext[BlockSize..];

        using var aes = Aes.Create();
        aes.Key = key.ToArray();

        Span<byte> padded = stackalloc byte[BlockSize], output = stackalloc byte[BlockSize];
        Pad(padded, tag, 1);
        aes.EncryptEcb(padded, output, PaddingMode.None);
        // Davies-Meyer
        XorBytes(padded, output);
        // Unmask padded plaintext
        XorBytes(padded, maskedPlaintext);

        Span<byte> computedTag = stackalloc byte[BlockSize];
        aes.EncryptEcb(padded, output, PaddingMode.None);
        padded.CopyTo(computedTag);
        // Davies-Meyer
        XorBytes(computedTag, output);

        try {
            if (!ConstantTime.Equals(tag, computedTag[..tag.Length])) {
                throw new CryptographicException();
            }

            int plaintextLength = padded[^1] / 8;
            if (plaintextLength > MaxInputSize || !ConstantTime.IsAllZeros(padded[plaintextLength..^1])) {
                throw new CryptographicException();
            }
            padded[..plaintextLength].CopyTo(plaintext);
            return plaintextLength;
        }
        finally {
            CryptographicOperations.ZeroMemory(padded);
            CryptographicOperations.ZeroMemory(output);
            CryptographicOperations.ZeroMemory(computedTag);
        }
    }

    private static void Pad(Span<byte> padded, ReadOnlySpan<byte> unpadded, byte value)
    {
        unpadded.CopyTo(padded);
        // Pad with 0s or 1s if unpadded.Length < MaxInputSize
        for (int i = unpadded.Length; i < padded.Length - 1; i++) {
            padded[i] = value;
        }
        // Encode the length (in bits) to reverse the padding
        // This is what reduces the committing security level
        padded[^1] = (byte)(unpadded.Length * 8);
    }

    private static void XorBytes(Span<byte> output, ReadOnlySpan<byte> input)
    {
        for (int i = 0; i < output.Length; i++) {
            output[i] ^= input[i];
        }
    }
}
