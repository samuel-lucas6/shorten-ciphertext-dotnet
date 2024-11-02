using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace ShortenCiphertextDotNet;

public static class ShortenCiphertext
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;

    // The ciphertext expansion depends on the plaintext length
    // If the plaintext is long enough (120+ bits - the cutoff), the expansion is equal to ChaCha20-Poly1305 (128 bits)
    // Otherwise, there's more expansion than ChaCha20-Poly1305 (128 + 120 bits)
    public static int GetCiphertextLength(int plaintextLength)
    {
        if (plaintextLength >= HashThenMask.PlaintextSize) {
            return plaintextLength + ChaCha20Poly1305.TagSize;
        }
        return HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize;
    }

    // For short plaintexts, the user has to manually truncate the span after decryption
    // This is because the length isn't known until you unpad
    public static int GetPlaintextLength(int ciphertextLength)
    {
        return ciphertextLength - ChaCha20Poly1305.TagSize;
    }

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, GetCiphertextLength(plaintext.Length));
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        bool smallPlaintext = plaintext.Length <= HashThenMask.PlaintextSize;
        Span<byte> aeadCiphertext = smallPlaintext ? ciphertext[..ChaCha20Poly1305.TagSize] : ciphertext[..^HashThenMask.PlaintextSize];
        ChaCha20Poly1305.Encrypt(aeadCiphertext, smallPlaintext ? ReadOnlySpan<byte>.Empty : plaintext[..^HashThenMask.PlaintextSize], nonce, key, associatedData: ReadOnlySpan<byte>.Empty);

        Span<byte> ctyTag = stackalloc byte[BLAKE2b.TagSize];
        using var blake2b = new IncrementalBLAKE2b(ctyTag.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Update(aeadCiphertext[^ChaCha20Poly1305.TagSize..]);
        blake2b.Finalize(ctyTag);

        HashThenMask.Encrypt(ciphertext[^(HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize)..], smallPlaintext ? plaintext : plaintext[^HashThenMask.PlaintextSize..], ctyTag);
        CryptographicOperations.ZeroMemory(ctyTag);
    }

    public static int Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, GetPlaintextLength(ciphertext.Length));
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize], poly1305Key = block0[..Poly1305.KeySize];
        ChaCha20.Fill(block0, nonce, key);

        ReadOnlySpan<byte> aeadCiphertext = ciphertext.Length <= HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize ? ReadOnlySpan<byte>.Empty : ciphertext[..^(HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize)];
        Span<byte> padding = stackalloc byte[16], poly1305Tag = padding[..Poly1305.TagSize];
        padding.Clear();
        using var poly1305 = new IncrementalPoly1305(poly1305Key);
        // No associatedData so no associatedData padding either
        poly1305.Update(aeadCiphertext);
        if (aeadCiphertext.Length % 16 != 0) {
            poly1305.Update(padding[(aeadCiphertext.Length % 16)..]);
        }
        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], 0);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)aeadCiphertext.Length);
        poly1305.Update(padding);
        poly1305.Finalize(poly1305Tag);
        CryptographicOperations.ZeroMemory(block0);

        Span<byte> ctyTag = stackalloc byte[BLAKE2b.TagSize];
        using var blake2b = new IncrementalBLAKE2b(ctyTag.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Update(poly1305Tag);
        blake2b.Finalize(ctyTag);
        CryptographicOperations.ZeroMemory(padding);

        Span<byte> paddedSuffix = stackalloc byte[HashThenMask.PlaintextSize];
        try {
            int suffixLength = HashThenMask.Decrypt(paddedSuffix, ciphertext[^(HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize)..], ctyTag);
            if (aeadCiphertext.Length != 0 && suffixLength != HashThenMask.PlaintextSize) {
                throw new CryptographicException();
            }
            paddedSuffix[..suffixLength].CopyTo(aeadCiphertext.Length == 0 ? plaintext : plaintext[^suffixLength..]);

            if (aeadCiphertext.Length == 0) {
                return suffixLength;
            }
            ChaCha20.Decrypt(suffixLength == 0 ? Span<byte>.Empty : plaintext[..^suffixLength], aeadCiphertext, nonce, key, counter: 1);
            return plaintext.Length;
        }
        finally {
            CryptographicOperations.ZeroMemory(ctyTag);
            CryptographicOperations.ZeroMemory(paddedSuffix);
        }
    }
}
