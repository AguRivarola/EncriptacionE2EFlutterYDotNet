using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using X25519;


namespace pocEncriptacion.Controllers;

[ApiController]
[Route("ecdh")]
public class WeatherForecastController : ControllerBase
{

    public class KeyRecibida
    {
        // public List<Byte> Key { get; set; }
        public String Key { get; set; }
    }

    public class MensajeEncriptado
    {
        // public List<Byte> Key { get; set; }
        public String mensaje { get; set; }
    }
    // {"Key":[247,193,136,116,186,149,81,204,162,74,149,9,203,69,39,55,155,191,239,193,120,181,163,198,225,181,233,174,14,62,37,59]}
    [HttpPost("ComunicacionSegura")]
    public string Post([FromBody] MensajeEncriptado encripted)
    {
        Console.WriteLine("Recibido desde Dart:");
        Console.WriteLine(encripted.mensaje);

        string decrypted = Decrypt(encripted.mensaje);

        Console.WriteLine("Mensaje desencriptado");
        Console.WriteLine(decrypted);
        
        return Encrypt("Vengo de .Net");
    }

    [HttpPost("IntercambioDeClaves")]
    public String Post([FromBody] KeyRecibida publicKeyAlice)
    {
        Console.WriteLine("Recibido:");
        Console.WriteLine(publicKeyAlice);
        Console.WriteLine(publicKeyAlice.Key);
        var keyPair = X25519KeyAgreement.GenerateKeyPair();
        string dartKey = publicKeyAlice.Key;
        byte[] sharedKeyBytes = X25519KeyAgreement.Agreement(keyPair.PrivateKey,
         Convert.FromBase64String(dartKey));
        Console.WriteLine("Secret generado: ");
        Console.WriteLine(Convert.ToBase64String(sharedKeyBytes));
        key = Convert.ToBase64String(sharedKeyBytes);
        return Convert.ToBase64String(keyPair.PublicKey);
    }
    private string Decrypt(byte[] encryptedBytes, byte[] key, byte[] vector)
    {
        var aesAlgorithm = Aes.Create();
        aesAlgorithm.Padding = PaddingMode.PKCS7;
        var decryptor = aesAlgorithm.CreateDecryptor(key, aesAlgorithm.IV);
        var memoryStream = new MemoryStream(encryptedBytes);
        var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        var streamReader = new StreamReader(cryptoStream, System.Text.Encoding.UTF8);
        return streamReader.ReadToEnd();
    }
    public static string key;
    private const int Keysize = 256;
    private const int DerivationIterations = 100;

    public string Encrypt(string plainText)
    {
        var saltStringBytes = Generate256BitsOfRandomEntropy();
        var ivStringBytes = Generate256BitsOfRandomEntropy();
        var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
        using (var password = new Rfc2898DeriveBytes(key, saltStringBytes, DerivationIterations))
        {
            var keyBytes = password.GetBytes(Keysize / 8);
            using (var symmetricKey = new RijndaelManaged())
            {
                symmetricKey.BlockSize = 128;
                symmetricKey.Mode = CipherMode.CBC;
                //symmetricKey.Padding = PaddingMode.PKCS7;
                using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                            cryptoStream.FlushFinalBlock();
                            var cipherTextBytes = saltStringBytes;
                            cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                            cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                            memoryStream.Close();
                            cryptoStream.Close();
                            return Convert.ToBase64String(cipherTextBytes);
                        }
                    }
                }
            }
        }
    }

    private static byte[] Generate256BitsOfRandomEntropy()
    {
        var randomBytes = new byte[16];
        using (var rngCsp = new RNGCryptoServiceProvider())
        {
            rngCsp.GetBytes(randomBytes);
        }
        return randomBytes;
    }

    public string Decrypt(string cipherText)
    {
        string password = key;
        byte[] cipherBytes = Convert.FromBase64String(cipherText);
        using (Aes encryptor = Aes.Create())
        {
            var salt = cipherBytes.Take(16).ToArray();
            var iv = cipherBytes.Skip(16).Take(16).ToArray();
            var encrypted = cipherBytes.Skip(32).ToArray();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, salt, 100);
            encryptor.Key = pdb.GetBytes(32);
            encryptor.Padding = PaddingMode.PKCS7;
            encryptor.Mode = CipherMode.CBC;
            encryptor.IV = iv;
            using (MemoryStream ms = new MemoryStream(encrypted))
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (var reader = new StreamReader(cs, System.Text.Encoding.UTF8))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }
    }
}





/*        ECDiffieHellman eCDiffieHellman =  ECDiffieHellman.Create();
        ECCurve eCCurve = new ECCurve();
        eCDiffieHellman.GenerateKey(eCCurve);*/
//Console.WriteLine(publicKeyAlice.ToString());
// ECDHHandler handler = new ECDHHandler();
//handler.ConvertByteArrayToPublicKey(publicKeyAlice);
//Console.WriteLine(handler.getPublicKey());
//Console.WriteLine(publicKeyAlice["Key"]);
// var b =new int[] {45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 116, 108, 50, 84, 80, 50, 67, 117, 85, 90, 120, 71, 47, 85, 71, 85, 114, 121, 116, 101, 83, 97, 69, 85, 55, 56, 50, 71, 10, 115, 118, 83, 108, 106, 110, 72, 52, 71, 79, 107, 118, 114, 103, 72, 113, 47, 77, 97, 89, 49, 103, 119, 87, 86, 48, 103, 48, 66, 113, 52, 115, 83, 70, 97, 98, 54, 117, 98, 75, 102, 70, 81, 113, 74, 106, 120, 54, 103, 112, 49, 65, 97, 89, 54, 76, 48, 81, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45}; 
//byte[] result = new byte[b.Length * sizeof(int)];
//Buffer.BlockCopy(b, 0, result, 0, result.Length);
//byte[] bytes = b.SelectMany(BitConverter.GetBytes).ToArray(); 
//Console.WriteLine(bytes);
//ECDiffieHellmanPublicKey keyRecibida = handler.ConvertByteArrayToPublicKey(bytes);
// Console.WriteLine(handler.getPublicKey());