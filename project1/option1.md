Option 1: Public-key encrypted message and its authentic digital digest
    • In this option, X is the sender and Y is the receiver.
    • In the sender’s program in the directory “Sender”, calculate RSA-En Ky+ (AES-En Kxy (SHA256 (M)) || M)
    1 To test this program, the corresponding key files need to be copied here from the directory “KeyGen”
    2 Read the information on the keys to be used in this program from the key files and generate Ky+ and Kxy.
    3 Display a prompt “Input the name of the message file:” and take a user input from the keyboard. This
    user input provides the name of the file containing the message M. M can NOT be assumed to be a text message. The
    size of the message M could be much larger than 32KB.
    4 Read the message, M, from the file specified in Step 3 piece by piece, where each piece is recommended to be a small
    multiple of 1024 bytes, calculate the SHA256 hash value (digital digest) of the entire message M, i.e., SHA256(M),
    SAVE it into a file named “message.dd”, and DISPLAY SHA256(M) in Hexadecimal bytes.
    5 Calculate the AES Encryption of SHA256(M) using Kxy (NO padding is allowed or needed here. Question: how many
    bytes are there in total?), SAVE this AES cyphertext into a file named “message.add-msg”, and DISPLAY it in
    Hexadecimal bytes. APPEND the message M read from the file specified in Step 3 to the file “message.add-msg” piece
    by piece.
    6 Calculate the RSA Encryption of (AES-En Kxy (SHA256 (M)) || M) using Ky+ by reading the file “message.add-msg”
    piece by piece, where each piece is recommended to be 117 bytes if "RSA/ECB/PKCS1Padding" is used. (Hint: if the
    length of the last piece is less than 117 bytes, it needs to be placed in a byte array whose array size is the length of the
    last piece before being encrypted.) SAVE the resulting blocks of RSA ciphertext into a file named “message.rsacipher”.
    • In the receiver’s program in the directory “Receiver”, using RSA and AES Decryptions to get SHA256 (M) and M, compare
    SHA256(M) with the locally calculated SHA256 hash of M, report hashing error if any, and then save M to a file.
    1 To test this program, the corresponding key files need to be copied here from the directory “KeyGen”, and the file
    “message.rsacipher” needs to be copied here from the directory “Sender”.
    MSU Denver, M&CS CS 3750-001: Computer and Network Security, Fall 2019 Dr. Weiying Zhu
    2 Read the information on the keys to be used in this program from the key files and generate Ky– and Kxy.
    3 Display a prompt “Input the name of the message file:” and take a user input from the keyboard. The
    resulting message M will be saved to this file at the end of this program.
    4 Read the ciphertext, C, from the file “message.rsacipher” block by block, where each block is recommended to be 128
    byte long if “RSA/ECB/PKCS1Padding” is used. Calculate the RSA Decryption of C using Ky– block by block to get
    AES-En Kxy (SHA256 (M)) || M, and save the resulting pieces into a file named “message.add-msg”.
    5 Read the first 32 bytes from the file “message.add-msg” to get the authentic digital digest AES-En Kxy (SHA256 (M)),
    and copy the message M, i.e., the leftover bytes in the file “message.add-msg”, to a file whose name is specified in Step
    3 (Why 32 bytes? Why is the leftover M?) Calculate the AES Decryption of this authentic digital digest using Kxy to
    get the digital digest SHA256(M), SAVE this digital digest into a file named “message.dd”, and DISPLAY it in
    Hexadecimal bytes.
    6 Read the message M from the file whose name is specified in Step 3 piece by piece, where each piece is recommended to
    be a small multiple of 1024 bytes, calculate the SHA256 hash value (digital digest) of the entire message M, compare it
    with the digital digest obtained in Step 5, and display whether the digital digest passes the authentication check