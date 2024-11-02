using System.Security.Cryptography;

namespace ShortenCiphertextDotNet.Tests;

[TestClass]
public class ShortenCiphertextTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "3b5212a66f943bf50dede8aa766d076e4eab4c303077f43a6ebf9e297e8f4a",
            "",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        ];
        yield return
        [
            "1d18cbaad43f7239c35af167ef296c070caa9f74f933a7236dacaa8f98e377",
            "4c61646965732061",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            ""
        ];
        yield return
        [
            "d3b3572cda3e25b5604c8c02abd481a3277c4d9cc16744eabf2d2d4a1f3ef599",
            "4c616469657320616e642047656e746c",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            ""
        ];
        yield return
        [
            "d31a8d34648e60db7b1f5dd1fff2c31d2f7085233f2e4d550ed9f6a7b660180c1c6ba8fe528a8db3",
            "4c616469657320616e642047656e746c656d656e206f6620",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            ""
        ];
        yield return
        [
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4de4e8f39f0aaef9d999654a74d9fdd4f43b81ef1c8a42edd2180209cb34ce9b9",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize - 1, 0, ShortenCiphertext.NonceSize, ShortenCiphertext.KeySize, HashThenMask.KeySize ];
        yield return [ HashThenMask.MaskedPlaintextSize + HashThenMask.MaxTagSize - 1, HashThenMask.PlaintextSize - 1, ShortenCiphertext.NonceSize, ShortenCiphertext.KeySize, HashThenMask.KeySize ];
        yield return [ HashThenMask.PlaintextSize + HashThenMask.MaxTagSize, HashThenMask.PlaintextSize, ShortenCiphertext.NonceSize, ShortenCiphertext.KeySize, HashThenMask.KeySize ];
        yield return [ HashThenMask.PlaintextSize + HashThenMask.MaskedPlaintextSize, HashThenMask.PlaintextSize, ShortenCiphertext.NonceSize + 1, ShortenCiphertext.KeySize, HashThenMask.KeySize ];
        yield return [ HashThenMask.PlaintextSize + HashThenMask.MaskedPlaintextSize, HashThenMask.PlaintextSize, ShortenCiphertext.NonceSize - 1, ShortenCiphertext.KeySize, HashThenMask.KeySize ];
        yield return [ HashThenMask.PlaintextSize + HashThenMask.MaskedPlaintextSize, HashThenMask.PlaintextSize, ShortenCiphertext.NonceSize, ShortenCiphertext.KeySize + 1, HashThenMask.KeySize ];
        yield return [ HashThenMask.PlaintextSize + HashThenMask.MaskedPlaintextSize, HashThenMask.PlaintextSize, ShortenCiphertext.NonceSize, ShortenCiphertext.KeySize - 1, HashThenMask.KeySize ];
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[ShortenCiphertext.GetCiphertextLength(p.Length)];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        ShortenCiphertext.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ShortenCiphertext.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> p = stackalloc byte[ShortenCiphertext.GetPlaintextLength(c.Length)];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        int plaintextLength = ShortenCiphertext.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p[..plaintextLength]).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };
        var p = new byte[ShortenCiphertext.GetPlaintextLength(parameters[0].Length)];

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            for (int i = 0; i < param.Length; i += param.Length - 1) {
                param[i]++;
                Assert.ThrowsException<CryptographicException>(() => ShortenCiphertext.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
                param[i]--;
            }
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ShortenCiphertext.Decrypt(p, c, n, k, ad));
    }
}
