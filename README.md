# EncriptacionE2EFlutterYDotNet
Poc de E2EE con ECDiffieHellman entre dart y .Net6 
Utilizacion de intercambio de claves de manera publica, generado de secret y encriptado/desencriptado en las puntas para comunicacion segura

## Tecnologias Utilizadas:

- Curva: x25519
- Padding: PKCS7
- Keysize: 256
- Iteraciones de derivacion: 100
- Encriptacion: AES con CBC
- Derivacion clave : PBKDF2 (SHA-1/HMAC/PBKDF2)
- IV: 16bytes
- salt: 16bytes

- Dart 3.0.6
  - 
      - basic_utils: ^5.6.0
      - crypto_keys: ^0.3.0+1
      - cryptography: ^2.5.0
      - http: ^1.1.0
      - pointycastle: ^3.7.3
      - convert: ^3.0.0
      - encrypt: ^5.0.1
      - aes256gcm: ^1.0.1
- DotNet 6.0
  - 
      - [X25519](https://www.nuget.org/packages/Easy-X25519)
      - 
   

## DotNet (.Net 6.0)
Posicionarse en la carpeta de proyecto dart:
```
cd dotNet/poc_encriptacion
```

Buildear el proyecto
```
dotnet build
```

Correr dll para levantar api:
``` 
dotnet run obj/Debug/net6.0/pocEncriptacion.dll
```


## Dart 
>***(En otra consola para que pueda seguir corriendo el dll)***

Posicionarse en la carpeta de proyecto dart:
```
cd poc_encriptacion
```

Instalar dependencias necesarias: (declaradas en pubspec.yml)
```
dart pub get
```

Correr metodo main:
``` 
dart run bin/poc_encriptacion.dart
```
