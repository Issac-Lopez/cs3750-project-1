# cs3750-project-1
cs3750 project 1
Project 1:
this give a more simplified overview of the tasks needed for completion on p1.

Task 1:
- symmetric key generation program -->(5 files) I/O
    - symmetric.key --> txt file
      write(byte[] b, int off, int len), binary output, class BufferedOutputStream
    - XPublic.key	--> write
    - XPrivate.key	--> write
    - YPublic.key	--> write
    - YPrivate.key	--> write

Option 1: Public-key encrypted message and its authentic digital digest
- X is the sender and Y is the receiver
- KeyGen Class
  - Methods
    - main()
      - user input for symmetric.key
      - makes symmetric.key file
      - generates a key pair
      - store keys to files, read, encrypt & decrypt from files
      - write to files
    - saveToFile()
      - write to file
- Sender Class
  - Methods
    - main()
      - user input for message
      - encrypt message
      - sign message
      - write to file
    - readPublicKeyFromFile()
      - Try to read public key from file or catch exception
    - hashingMessage()
      - try to hash message or catch exception 
    - processFile()
      - try to process file or catch exception
      - read file, encrypt, sign, write to file
      - reduce cognitive complexity*
    - appendToFile()
      - try to append to file or catch exception
- Receiver Class
  - Methods
    - main()
      - read file
      - decrypt message
      - verify message
      - write to file
    - readPrivateKeyFromFile()
      - Try to read private key from file or catch exception
    - hashingMessage()
      - try to hash message or catch exception
    - processFile()
      - try to process file or catch exception
      - read file, decrypt, verify, write to file
      - reduce cognitive complexity*
    - getHashAndMessageFiles()
      - try to get hash and message files or catch exception
    - getHasMadeBySender()
      - try to get hash made by sender or catch exception

Task 2 (Classes):
- test in the VS
Task 3:
- presentation and demo