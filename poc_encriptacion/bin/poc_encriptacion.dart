import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as crypt;
import 'package:http/http.dart';
import 'dart:math';
import 'package:pointycastle/export.dart';

Future<void> main(List<String> arguments) async {
  //https://pub.dev/documentation/cryptography/latest/cryptography/X25519-class.html

  final algorithm = crypt.Cryptography.instance.x25519();
  final keyPair = await algorithm.newKeyPair();
  crypt.SimplePublicKey publicKey = await keyPair.extractPublicKey();
  //saving key bytes as base64 string
  String keyPublicaDart = base64.encode(publicKey.bytes);
  print("Key actual");
  print(keyPublicaDart);

  String remoteKeyBase64 = await enviarKeys(keyPublicaDart);

  print("Key .Net");
  print(remoteKeyBase64);

  crypt.SimplePublicKey remotePublicKey = crypt.SimplePublicKey(
      base64.decode(remoteKeyBase64),
      type: crypt.KeyPairType.x25519);
  final sharedSecretKey = await algorithm.sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: remotePublicKey,
  );

  List<int> sharedKeyBytes = await sharedSecretKey.extractBytes();
  final privateKeyGenerada = base64.encode(sharedKeyBytes);
  print("Secret:");
  print(privateKeyGenerada);
  Uint8List plaintext =
      Uint8List.fromList(utf8.encode("{\"name\":\"nombredePrueba[]\"}"));
  Uint8List passphrase = Uint8List.fromList(utf8.encode(privateKeyGenerada));

  // Generate random 16 bytes salt and random 16 bytes IV
  SecureRandom secureRandom = getSecureRandom();
  Uint8List salt = secureRandom.nextBytes(16);
  Uint8List iv = secureRandom.nextBytes(16);

// Derive 32 bytes key via PBKDF2
  Uint8List key = deriveKey(salt, passphrase);

// Encrypt with AES-256/CBC/PKCS#7 padding
  Uint8List ciphertext = encryptAesCbcPkcs7(plaintext, key, iv);

// Concat salt|nonce|ciphertext and Base64 encode
  String saltIvCiphertextB64 = concatAndEncode(salt, iv, ciphertext);
  // print("Mensaje encriptado desde Dart");
  // print(saltIvCiphertextB64);
  // String retorno = await enviarMensajeEncriptado(saltIvCiphertextB64);
  String retorno = await getCertificates(saltIvCiphertextB64);
  print("Mensaje retornado desde .Net");
  print(retorno);
  desencript(retorno, passphrase);
}

String urlBase = "https://localhost:7151/Encustody";
String tokenDotNet =
    "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJSMlpCUGNrZW9wUUh2WjVWSXVsc2JxaTBfQXZVZkpPTUhaNTQ4N0xXNVpZIn0.eyJqdGkiOiI5ZDM4OGViNS03YzEyLTQzYjUtYTg4Mi1iOTgxYzQ4Y2NjZjkiLCJleHAiOjE2ODkxMzE2NDgsIm5iZiI6MCwiaWF0IjoxNjg5MDk1NjQ4LCJpc3MiOiJodHRwczovL2F1dGgtdGVzdC5lbmN1c3RvZHkuY29tLmFyL2F1dGgvcmVhbG1zL0VOQ09ERSIsImF1ZCI6WyJzaWduYXR1cmUtc2VydmljZSIsImFjY291bnQiXSwic3ViIjoiOWI1M2MzNzYtOGYxNS00MjA5LWIzZjYtODRhZTNhYzVmMTY0IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoic2VydmljaW8tY3VzdG9kaWEiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiIyNjcwYmViYS1jOWUxLTQwNTctOWQ1MC03NDk1YmQ1ZTIyODUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHBzOi8vZmlybWFkb3ItdGVzdC5lbmN1c3RvZHkuY29tLmFyLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIiwiY2EiXX0sInJlc291cmNlX2FjY2VzcyI6eyJzaWduYXR1cmUtc2VydmljZSI6eyJyb2xlcyI6WyJtYW5hZ2UtY3VzdG9tZXJzIiwibWFuYWdlLXNpZ25pbmctcmVxdWVzdCIsInZpZXctc2lnbmluZy1yZXF1ZXN0Il19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkZhY3VuZG8gWmVycGEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiIyMDM2MjI1Mzg1NCIsImdpdmVuX25hbWUiOiJGYWN1bmRvIiwibG9jYWxlIjoiZXMiLCJmYW1pbHlfbmFtZSI6IlplcnBhIiwiZW1haWwiOiJmemVycGFAZW5jb2Rlc2EuY29tLmFyIn0.PhXHPxjG3Aclv-sLsbQ92lCuc3ly-YT25nZyl3tFl9YMOKGRC8bVMAey-r0YbcodPaNH4qsMjgsYxSjSfkz_it41Lc82cxLSByFCJPa17f_MUXqxIp2CjpKjq4TsKODtd28xoADMjNJO9ps5WXNt5jlG_jkAnDmhZYGvJ5dhnrUwoyktdyNV3L-b-ttV-A4kC1r2q3ZZ387KxASF8_eV6uWyxX_rCH3p9OGRJwy4jYBulb8YJo45dRS1Xj5QO6R4IyC-cnUmzsXNoPk59Uc8j9c2XlEeFTIPDCLZ5bAe6SIFFsHMbCuM-DhRsDebfRac8N0BL84rzLxi3zfnS8rhLA";

Future<String> enviarKeys(String publicKey) async {
  final response = await post(
    Uri.parse(urlBase + '/changeKey'),
    headers: <String, String>{
      'Content-Type': 'application/json; charset=UTF-8',
    },
    body: jsonEncode(<String, String>{'Key': publicKey, 'Cuil': "20362253854"}),
  );
  if (response.statusCode == 200) {
    return response.body;
  } else {
    throw Exception('No se pudo realizar el intercambio de ECDH');
  }
}

Future<String> enviarMensajeEncriptado(String mensaje) async {
  final response = await post(
    Uri.parse(urlBase + '/chatSecurity'),
    headers: <String, String>{
      'Content-Type': 'application/json; charset=UTF-8',
    },
    body:
        jsonEncode(<String, String>{'Message': mensaje, 'Cuil': "21412657188"}),
  );
  if (response.statusCode == 200) {
    return response.body;
  } else {
    throw Exception('No se pudo realizar el intercambio de mensaje seguro');
  }
}

Future<String> getCertificates(String mensaje) async {
  final response = await post(
    Uri.parse(urlBase + '/certificates'),
    headers: <String, String>{
      'Content-Type': 'application/json; charset=UTF-8',
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + tokenDotNet,
    },
  );

  if (response.statusCode == 200) {
    return response.body;
  } else {
    print(response.statusCode);
    throw Exception('No se pudo realizar el intercambio de mensaje seguro');
  }
}

String concatAndEncode(Uint8List salt, Uint8List iv, Uint8List ciphertext) {
  BytesBuilder saltIvCiphertext = BytesBuilder();
  saltIvCiphertext.add(salt);
  saltIvCiphertext.add(iv);
  saltIvCiphertext.add(ciphertext);
  String saltIvCiphertextB64 = base64Encode(saltIvCiphertext.toBytes());
  return saltIvCiphertextB64;
}

Uint8List encryptAesCbcPkcs7(Uint8List plaintext, Uint8List key, Uint8List iv) {
  CBCBlockCipher cipher = CBCBlockCipher(AESEngine());
  ParametersWithIV<KeyParameter> params =
      ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
  PaddedBlockCipherParameters<ParametersWithIV<KeyParameter>, Null>
      paddingParams =
      PaddedBlockCipherParameters<ParametersWithIV<KeyParameter>, Null>(
          params, null);
  PaddedBlockCipherImpl paddingCipher =
      PaddedBlockCipherImpl(PKCS7Padding(), cipher);
  paddingCipher.init(true, paddingParams);
  Uint8List ciphertext = paddingCipher.process(plaintext);
  return ciphertext;
}

Uint8List deriveKey(Uint8List salt, Uint8List passphrase) {
  KeyDerivator derivator = KeyDerivator('SHA-1/HMAC/PBKDF2');
  Pbkdf2Parameters params = Pbkdf2Parameters(salt, 100, 256 ~/ 8);
  derivator.init(params);
  return derivator.process(passphrase);
}

SecureRandom getSecureRandom() {
  List<int> seed = List<int>.generate(32, (_) => Random.secure().nextInt(256));
  return FortunaRandom()..seed(KeyParameter(Uint8List.fromList(seed)));
}

///*//
///
///
///
///
///*/*/*/*/** */
void desencript(String encrypted, Uint8List passphrase) {
  String saltIvCiphertextB64 = encrypted; // Obtén el valor cifrado en Base64

  Uint8List salt, iv, ciphertext;
  // Decodifica el valor cifrado en Base64 y obtén salt, iv y ciphertext
  Uint8List saltIvCiphertext = base64Decode(saltIvCiphertextB64);
  salt = saltIvCiphertext.sublist(0, 16);
  iv = saltIvCiphertext.sublist(16, 32);
  ciphertext = saltIvCiphertext.sublist(32);

  Uint8List key = deriveKey(salt, passphrase);

  Uint8List decryptedText = decryptAesCbcPkcs7(ciphertext, key, iv);

  String plaintext = utf8.decode(decryptedText);

  print("Mensaje desencriptado recibido desde .Net");
  print(plaintext);
}

void decodeAndSplit(String saltIvCiphertextB64, Uint8List salt, Uint8List iv,
    Uint8List ciphertext) {}

Uint8List decryptAesCbcPkcs7(
    Uint8List ciphertext, Uint8List key, Uint8List iv) {
  CBCBlockCipher cipher = CBCBlockCipher(AESEngine());
  ParametersWithIV<KeyParameter> params =
      ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
  PaddedBlockCipherParameters<ParametersWithIV<KeyParameter>, Null>
      paddingParams =
      PaddedBlockCipherParameters<ParametersWithIV<KeyParameter>, Null>(
          params, null);
  PaddedBlockCipherImpl paddingCipher =
      PaddedBlockCipherImpl(PKCS7Padding(), cipher);
  paddingCipher.init(false, paddingParams);
  Uint8List decryptedText = paddingCipher.process(ciphertext);
  return decryptedText;
}
