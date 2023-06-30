import 'package:cryptography/cryptography.dart';
import 'dart:convert';

import 'package:http/http.dart';

Object getMDoc() {
  return {
    "test": "test",
    "test2": {"a": "b"},
    "test3": 3
  };
}

Future<SimpleKeyPair> generateEDeviceKeyPair() async {
  final algorithm = X25519();

  final keyPair = await algorithm.newKeyPair();

  return keyPair;
}

// Changed algorithm to X25519
Future<SimpleKeyPair> generateEReaderKeyPair() async {
  final algorithm = X25519();

  final keyPair = await algorithm.newKeyPair();

  return keyPair;
}

// Generated a sharedSecretKey to derive the session key
Future<SecretKey> generateSKDevice(
    SimpleKeyPairData eDeviceKeyPriv, SimplePublicKey eReaderKeyPub) async {
  final algorithm = X25519();

  final sharedSecretKey = await algorithm.sharedSecretKey(
      keyPair: eDeviceKeyPriv, remotePublicKey: eReaderKeyPub);

  final deriveAlgorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );

  final skDevice = await deriveAlgorithm.deriveKey(
      secretKey: sharedSecretKey,
      info: utf8.encode("UTF8"),
      nonce: <int>[1, 2]);

  return skDevice;
}

Future<SecretKey> generateSKReader(
    SimpleKeyPairData eReaderKeyPriv, SimplePublicKey eDeviceKeyPub) async {
  // final algorithm = Ecdh.p256(length: 256);
  final algorithm = X25519();

  final sharedSecret = await algorithm.sharedSecretKey(
      keyPair: eReaderKeyPriv, remotePublicKey: eDeviceKeyPub);

  final deriveAlgorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );

  final output = await deriveAlgorithm.deriveKey(
      secretKey: sharedSecret, info: utf8.encode("UTF8"), nonce: <int>[1, 2]);

  return output;
}

Future<SecretBox> encryptMDocResponse(
    Object mdocResponse, SecretKey skDevice) async {
  final algorithm = AesGcm.with256bits();

  final secretBox = await algorithm.encrypt(
    utf8.encode(json.encode(mdocResponse)),
    secretKey: skDevice,
  );

  return secretBox;
}

Future<List<int>> decryptMDocResponse(
    SecretBox mdocResponse, SecretKey skReader) async {
  final algorithm = AesGcm.with256bits();

  final chipherText = await algorithm.decrypt(
    mdocResponse,
    secretKey: skReader,
  );

  return chipherText;
}

// Example of use
Future<void> main(List<String> arguments) async {
  // Holder: get mdoc
  final mdoc = getMDoc();

  // Holder & Reader: generate Ephemeral Keys
  final eDeviceKey = await generateEDeviceKeyPair();
  final eReaderKey = await generateEReaderKeyPair();

  // Holder: generate Session Key (skDevice)
  final skDevice = await generateSKDevice(
      await eDeviceKey.extract(), await eReaderKey.extractPublicKey());
  var publicKey = await eDeviceKey.extractPublicKey();

  // Holder: encrypt device response
  final response = await encryptMDocResponse(mdoc, skDevice);
  print("Response");
  print(response);

  // Reader: generate Session Key (skDevice)
  final skReader = await generateSKReader(
      await eReaderKey.extract(), await eDeviceKey.extractPublicKey());

  // Reader: decrypt device response
  final decrypted = await decryptMDocResponse(response, skReader); // Error here
  print("decrypted");
  print(utf8.decode(decrypted));
  enviarKeys(publicKey);
}

Future<List<int>> enviarKeys(SimplePublicKey publicKey) async {
  final response = await post(
    Uri.parse('https://localhost:7286/ecdh'),
    headers: <String, String>{
      'Content-Type': 'application/json; charset=UTF-8',
    },
    // body: publicKey.bytes,
    body: jsonEncode(<String, List<int>>{
      'Key': publicKey.bytes,
    }),
  );
  if (response.statusCode == 200) {
    // If the server did return a 201 CREATED response,
    // then parse the JSON.
    print(response.body);
    return jsonDecode(response.body);
  } else {
    // If the server did not return a 201 CREATED response,
    // then throw an exception.
    throw Exception('Failed to create album.');
  }
}
