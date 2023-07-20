# EncriptacionE2EFlutterYDotNet
Poc de E2EE con ECDiffieHellman entre dart y .Net6 
Utilizacion de intercambio de claves de manera publica, generado de secret y encriptado/desencriptado en las puntas para comunicacion segura

## Tecnologias Utilizadas:
- Dart 3.0.6
    - basic_utils: ^5.6.0
    - crypto_keys: ^0.3.0+1
    - cryptography: ^2.5.0
    - http: ^1.1.0
    - pointycastle: ^3.7.3
    - convert: ^3.0.0
    - encrypt: ^5.0.1
    - aes256gcm: ^1.0.1
- .Net 6.0
    - 

## DotNet (.Net 6.0)
Posicionarse en la carpeta de proyecto dart:
'''
cd dotNet/poc_encriptacion
'''

Buildear el proyecto
'''
dotnet build
'''

Correr dll para levantar api:
''' 
dotnet run obj/Debug/net6.0/pocEncriptacion.dll
'''


## Dart

Posicionarse en la carpeta de proyecto dart:
'''
cd poc_encriptacion
'''

Instalar dependencias necesarias: (declaradas en pubspec.yml)
'''
dart pub get
'''

Correr metodo main:
''' 
dart run bin/poc_encriptacion.dart
'''
