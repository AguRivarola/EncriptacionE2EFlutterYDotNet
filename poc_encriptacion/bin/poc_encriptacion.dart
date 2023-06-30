import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart';
import 'package:encrypt/encrypt.dart';
import 'package:aes256gcm/aes256gcm.dart';

Future<void> main(List<String> arguments) async {
  //https://pub.dev/documentation/cryptography/latest/cryptography/X25519-class.html

  final algorithm = Cryptography.instance.x25519();
  final keyPair = await algorithm.newKeyPair();
  SimplePublicKey publicKey = await keyPair.extractPublicKey();
  //saving key bytes as base64 string
  String keyPublicaDart = base64.encode(publicKey.bytes);
  print("Key actual");
  print(keyPublicaDart);

  String remoteKeyBase64 = await enviarKeys(keyPublicaDart);

  print("Key .Net");
  print(remoteKeyBase64);

  SimplePublicKey remotePublicKey =
      SimplePublicKey(base64.decode(remoteKeyBase64), type: KeyPairType.x25519);
  final sharedSecretKey = await algorithm.sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: remotePublicKey,
  );

  List<int> sharedKeyBytes = await sharedSecretKey.extractBytes();
  print(sharedKeyBytes);
  final privateKeyGenerada = base64.encode(sharedKeyBytes);
  print("Secret:");
  print(privateKeyGenerada);
  print("Key con 32 Char:");
  print(privateKeyGenerada.substring(11));

//https://pub.dev/packages/aes256gcm
  var text = 'SOME DATA TO ENCRYPT';
  var password = privateKeyGenerada.substring(11);

  var encrypted = await Aes256Gcm.encrypt(text, password);
  var decrypted = await Aes256Gcm.decrypt(encrypted as String, password);

  print(encrypted);
  print(decrypted);
  // final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  // final key = Key.fromUtf8('J2oeoj16Qx+KkTNglepNXFKehlwnB/nj');
  // final iv = IV.fromLength(16);

  // final encrypter = Encrypter(AES(key));

  // final encrypted = encrypter.encrypt(plainText, iv: iv);
  // final decrypted = encrypter.decrypt(encrypted, iv: iv);

  // print(decrypted); // Lorem ipsum dolor sit amet, consectetur adipiscing elit
  // print(encrypted.base64);
}

Future<String> enviarKeys(String publicKey) async {
  final response = await post(
    Uri.parse('https://localhost:7286/ecdh'),
    headers: <String, String>{
      'Content-Type': 'application/json; charset=UTF-8',
    },
    // body: publicKey.bytes,
    body: jsonEncode(<String, String>{
      'Key': publicKey,
    }),
  );
  if (response.statusCode == 200) {
    // If the server did return a 201 CREATED response,
    // then parse the JSON.
    return response.body;
  } else {
    // If the server did not return a 201 CREATED response,
    // then throw an exception.
    throw Exception('Failed to create album.');
  }
}
