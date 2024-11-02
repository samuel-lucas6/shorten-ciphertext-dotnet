using System.Security.Cryptography;

namespace ShortenCiphertextDotNet.Tests;

[TestClass]
public class HashThenMaskTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "4a774a6d90bc06d340056ecdd3003fc7602d846e",
            "",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        ];
        yield return
        [
            "5141e42cef906fabc4548bd335a6bf3aa4a5d791",
            "4c616469657320616e642047656e74",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        ];
        yield return
        [
            "b9f3617e499c6f8ea0a09bceaf497d40602d846ebd4a5431ba226be76d0bfc",
            "",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        ];
        yield return
        [
            "4f22d7c25a8ed72104b4a3ac90e08646a4a5d79153ea50aa78a043edb9d3fa",
            "4c616469657320616e642047656e74",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize + 1, HashThenMask.PlaintextSize, HashThenMask.KeySize ];
        yield return [ HashThenMask.MaskedPlaintextSize + HashThenMask.MinTagSize - 1, HashThenMask.PlaintextSize, HashThenMask.KeySize ];
        yield return [ HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize, HashThenMask.PlaintextSize + 1, HashThenMask.KeySize ];
        yield return [ HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize, HashThenMask.PlaintextSize, HashThenMask.KeySize + 1 ];
        yield return [ HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize, HashThenMask.PlaintextSize, HashThenMask.KeySize - 1 ];
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);

        HashThenMask.Encrypt(c, p, k);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HashThenMask.Encrypt(c, p, k));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key)
    {
        Span<byte> p = stackalloc byte[HashThenMask.PlaintextSize];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);

        int plaintextLength = HashThenMask.Decrypt(p, c, k);

        Assert.AreEqual(plaintext, Convert.ToHexString(p[..plaintextLength]).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string key)
    {
        var p = new byte[HashThenMask.PlaintextSize];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(key)
        };

        foreach (var param in parameters) {
            for (int i = 0; i < param.Length; i += param.Length - 1) {
                param[i]++;
                Assert.ThrowsException<CryptographicException>(() => HashThenMask.Decrypt(p, parameters[0], parameters[1]));
                param[i]--;
            }
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HashThenMask.Decrypt(p, c, k));
    }
}
