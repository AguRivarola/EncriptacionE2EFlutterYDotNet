using System;
using System.Security.Cryptography;
using System.Text;

public class ECDHHandler
{
    private ECDiffieHellmanPublicKey publicKey;
    private ECDiffieHellman keyAgreement;
    private byte[] sharedSecret;

    public ECDHHandler()
    {
        MakeKeyExchangeParams();
    }

    private void MakeKeyExchangeParams()
    {
        try
        {
            using (var keyPairGenerator = ECDiffieHellman.Create())
            {
                keyPairGenerator.GenerateKey(ECCurve.NamedCurves.nistP256);

                var publicKeyBytes = keyPairGenerator.PublicKey.ToByteArray();
                var privateKeyBytes = keyPairGenerator.ExportPkcs8PrivateKey();
                
                var x509DerFromDotNet = Convert.ToBase64String(publicKeyBytes);
                var pkcs8DerFromDotNet = Convert.ToBase64String(privateKeyBytes);
                Console.WriteLine(x509DerFromDotNet);        
                Console.WriteLine(pkcs8DerFromDotNet);        
                keyAgreement = keyPairGenerator;
                publicKey = keyPairGenerator.PublicKey;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.StackTrace);
        }
    }

    public void InitializeSharedSecret(ECDiffieHellmanPublicKey publicKey)
    {
        try
        {
            sharedSecret = keyAgreement.DeriveKeyMaterial(publicKey);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.StackTrace);
        }
    }
    public ECDiffieHellmanPublicKey getPublicKey(){
        return publicKey;
    }

    public ECDiffieHellmanPublicKey ConvertByteArrayToPublicKey(byte[] bytes)
{
    try
    {
        using (var keyProvider = new ECDiffieHellmanCng())
        {
            var keyBlob = new byte[bytes.Length + 12];
            keyBlob[0] = 0x06; // PUBLICKEYBLOB
            keyBlob[1] = 0x02; // CURVE

            Buffer.BlockCopy(bytes, 0, keyBlob, 12, bytes.Length);

            keyProvider.ImportSubjectPublicKeyInfo(keyBlob, out _);
            return keyProvider.PublicKey;
        }
    }
    catch (Exception e)
    {
        Console.WriteLine(e.StackTrace);
    }
    return null;
}
    
}