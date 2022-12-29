# Steps & Commands in PowerShell
1) Generate the symmetric, public, and private key's for the sender and receiver in using the KeyGen.java file in the KeyGen directory.
```
cd .\KeyGen\
javac KeyGen.java
java KeyGen
```
> Note: symmetric key = Kxy; Sender public key = Kx+; Sender private key = Kx-; Receiver public key = Ky+; Receiver private key = Ky-

2) Once code is compiled and ran, you will be prompted to created a 16 character `symmetric.key` from user's input. For example:
```
qwerty1234567890
```
> Note: Then, the `.key` files for the sender's public key and private key will be displayed along with the receiver's public key and private key. Can be viewed in directory using `ls`

6) The Sender is using this encryption algorithm RSA-En Ky+ (AES-En Kxy (SHA256 (M)) || M) and the Receiver uses an opposite decryption algorithm so, copy the correct keys into the correct directories from the `KeyGen` directory.
```
cp .\symmetric.key ..\Sender\
cp .\symmetric.key ..\Receiver\
cp .\YPublic.key ..\Sender\
cp .\YPrivate.key ..\Receiver\
```

7) Compile and run the `Sender.java` file and once prompted, enter in the example file being, `Garden.txt` OR `CS3700.htm`.
```
cd ..\Sender\
javac Sender.java
java Sender
```
> Note: Most types of file extensions should work once added to the `Sender` directory by user.

9) There will be three files that will have been created:
```
-a----        12/29/2022  12:13 PM           8451 message.add-msg
-a----        12/29/2022  12:13 PM             32 message.dd
-a----        12/29/2022  12:13 PM           9344 message.rsacipher
```
- `message.dd` - message digest which has been written to this file.
- `message.add-msg` - message that has been appended to this file.
- `message.rsacipher` - RSA encryption of symmetric key (Kxy) using public key (Ky+) and wrote to file.

10) Compile and run the `Receiver.java` file and once prompted, enter the file to put the decrypted message in file for example: `Garden-decrypted.txt` OR `CS3700-decrypted.htm`.
```
cd ..\Receiver\
javac Receiver.java
java Receiver
```
11) Once ran, and input of a decrypted file has been entered, you should have these new files in your `Receiver` directory:
```
-a----        12/29/2022   1:38 PM             32 aesTemp.dd
-a----        12/29/2022   1:38 PM           8419 garden-decrypted.txt
-a----        12/29/2022   1:38 PM           8451 message.add-msg
-a----        12/29/2022   1:38 PM             32 message.dd
```
- `aesTemp.dd` - temporary holder for RSA Decrypted-AES(SHA-256(M).
- `garden-decrypted.txt` - decrypted message from the sender.
- `message.add-msg` - message that has been appended to this file.
- `message.dd` - message digest used for comparison.

12) In the terminals output, once `Receiver.java` has been ran correctly, you can see the following:
```
==============================================
Decrypting RSA message...
==============================================
RSA message decrypted!
decrypted RSA (AES(SHA-256(M))||M)
53 C3 E9 35 60 38 D7 D1 D3 A0 67 EF  E 56 1D 15
DE CB A8 E9 A4 66 B2 E7 B5 96 D8 3B F7 E2 CE 49

Decrypted AES(SHA-256(M))
digit digest (hash value):
AD EC 5F 1B 4F FA CD 6D 30 CE 2C 8F D7 94 FF DD
26 55 8B 2D 1A BD F5 8C 5D A7 D8 D4  9 44 3A 46

Message Digest of extracted message
digit digest (hash value):
AD EC 5F 1B 4F FA CD 6D 30 CE 2C 8F D7 94 FF DD
26 55 8B 2D 1A BD F5 8C 5D A7 D8 D4  9 44 3A 46
==============================================
The message digest used for comparison
==============================================
digit digest (hash value):
AD EC 5F 1B 4F FA CD 6D 30 CE 2C 8F D7 94 FF DD
26 55 8B 2D 1A BD F5 8C 5D A7 D8 D4  9 44 3A 46
==============================================
Comparing the message digest of the message
file with the message digest of the decrypted message
==============================================
The message digest of the message file matches
the message digest of the decrypted message
==============================================
```
This message confirming that the encryption and decryption successfully worked!

> Note: You can use the following commands to redirect the standard output (stdout) to a file and view the contents of the file:
```
java Receiver | tee testResults.txt //copy stdout to the .txt file
cat testResults.txt //display the file’s contents
```
If there is anything that I missed or does not make sense, please reach out to me and I would be happy to help!😄
