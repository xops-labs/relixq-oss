using System.Security.Cryptography;

namespace Example.Crypto;

public static class CryptoService
{
    public static RSA CreateRsa() => new RSACryptoServiceProvider(2048);

    public static ECDsa CreateSigner() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static TripleDES CreateLegacyCipher() => new TripleDESCryptoServiceProvider();

    public static Aes CreateSessionCipher()
    {
        var aes = Aes.Create();
        aes.KeySize = 256;
        return aes;
    }

    public static byte[] Digest(byte[] data) => SHA512.HashData(data);
}
