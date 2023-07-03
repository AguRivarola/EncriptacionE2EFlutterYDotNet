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
  print("Mensaje encriptado desde Dart");
  print(saltIvCiphertextB64);
  String retorno = await enviarMensajeEncriptado(saltIvCiphertextB64);
  print("Mensaje retornado desde .Net");
  print(retorno);
  desencript(retorno, passphrase);
}

Future<String> enviarKeys(String publicKey) async {
  final response = await post(
    Uri.parse('https://localhost:7286/ecdh/IntercambioDeClaves'),
    headers: <String, String>{
      'Content-Type': 'application/json; charset=UTF-8',
    },
    body: jsonEncode(<String, String>{
      'Key': publicKey,
    }),
  );
  if (response.statusCode == 200) {
    return response.body;
  } else {
    throw Exception('No se pudo realizar el intercambio de ECDH');
  }
}

Future<String> enviarMensajeEncriptado(String mensaje) async {
  final response = await post(
    Uri.parse('https://localhost:7286/ecdh/ComunicacionSegura'),
    headers: <String, String>{
      'Content-Type': 'application/json; charset=UTF-8',
    },
    body: jsonEncode(<String, String>{
      'mensaje': mensaje,
    }),
  );
  if (response.statusCode == 200) {
    return response.body;
  } else {
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
