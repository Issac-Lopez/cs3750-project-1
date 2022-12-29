import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is used to decrypt the encrypted message from the sender
 * It uses the symmetric key and the private key of the receiver to decrypt the
 * message
 * It also uses the public key of the sender to verify the signature
 * The decrypted message is then written to a file called from user input
 */
public class Receiver {
    public static void main(String[] args) throws Exception {
        String IV = "AAAAAAAAAAAAAAAA";
        String symmetricKeyFileName = "symmetric.key";
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        String rsaEncryptedMessage = "../Sender/message.rsacipher";
        String rsaDecryptedMdandMessage = "message.add-msg";
        String messageDigest = "message.dd";
        // Copy Keys to sender program
        String YPrivateKeyFilePath = "YPrivate.key";
        PrivateKey yPrivKey = readPrivKeyFromFile(YPrivateKeyFilePath); // Ky-
        String symmetricKey = readSymmetricKeyFromFile(symmetricKeyFileName); // Kxy
        // Ask user for Message file name
        Scanner scn = new Scanner(System.in);
        System.out.println("==================================================================");
        System.out.println("== Input the name of the message file you would like to save to ==");
        System.out.println("==================================================================");
        System.out.println();
        String messageFileName = scn.nextLine(); // The name of the message file
        // same as the AES encrypted message + original message
	System.out.println("==============================================");
        System.out.println("Decrypting RSA message...");
	System.out.println("==============================================");
        decryptRSA(rsaEncryptedMessage, rsaDecryptedMdandMessage, cipher, yPrivKey); // decrypt the message using the
                                                                                     // private key of the receiver
        System.out.println("RSA message decrypted!");
        // Extract AES message digest from file after RSA decryption
        System.out.println("Extract AES message digest from file RSA Decrypted file after RSA decryption");
        String tempFile = "aesTemp.dd"; // tmp holder for [RSA Decrypted-AES(SHA-256(M)]
        extractMdandMessage(rsaDecryptedMdandMessage, tempFile, messageFileName);
        byte[] rsaDecryptedMd = readToFile(tempFile); // [RSA Decrypted-AES(SHA-256(M)]
        System.out.println("decrypted RSA (AES(SHA-256(M))||M)");
        convertHex(rsaDecryptedMd); //
        System.out.println("");
        // AES decryption of the rsaDecryptedMessage.dd same as the message digest
        decryptAES(tempFile, messageDigest, symmetricKey, IV); // AES decypted file conataining the rsa decrypted
                                                               // message digest and write aes decryption to file
        byte[] rsaAESDecrypted = readToFile(messageDigest); // read the aes decrypted file and return it as a byte array
        System.out.println("Decrypted AES(SHA-256(M))");
        convertHex(rsaAESDecrypted);
        System.out.println(" ");
        System.out.println("Message Digest of extracted message");
        MessageDigest md = md(messageFileName); // provides message digest of messagefile
        byte[] hash = md.digest(); // turns the message digest into a byte array called hash
        convertHex(hash);
        System.out.println("==============================================");
        System.out.println("The message digest used for comparison");
        System.out.println("==============================================");
        byte[] messageDD = readToFile("../Sender/message.dd");
        convertHex(messageDD);
        // Compare the message digest of the message file with the message digest of the
        // decrypted message
        System.out.println("==============================================");
        System.out.println(
                "Comparing the message digest of the message \nfile with the message digest of the decrypted message");
        System.out.println("==============================================");
        if (compare(hash, messageDD)) {
            System.out.println(
                    "The message digest of the message file matches \nthe message digest of the decrypted message");
	    System.out.println("==============================================");
        } else {
            System.out.println("==============================================");
            System.out.println(
                    "The message digest of the message file does \nnot match the message digest of the decrypted message!!");
            System.out.println("==============================================");
        }
    }

    // this method Compares the message digest of the message file with the message
    // digest of the decrypted message
    public static boolean compare(byte[] hash, byte[] messageDD) {
        if (hash.length != messageDD.length) {
            return false;
        }
        for (int i = 0; i < hash.length; i++) {
            if (hash[i] != messageDD[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * This method is used to extract the message digest and the message from the
     * file containing the RSA decrypted message.
     * 
     * @param fileToExtractFrom    The file containing the RSA decrypted message
     * @param tempFile             The file to write the extracted message digest to
     * @param fileToExtractMessage The file to write the extracted message to
     */
    public static void extractMdandMessage(String fileToExtractFrom, String tempFile, String fileToExtractMessage) {
        try { // try to extract the message digest and the message from the file containing
              // the RSA decrypted message
            int BUFFER_SIZE = 32; // buffer size
            int mBUFFER_SIZE = 1024; // message buffer size
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToExtractFrom)); // read
                                                                                                                       // file
                                                                                                                       // to
                                                                                                                       // buffer
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(tempFile));
            BufferedOutputStream bufferedOutputStream1 = new BufferedOutputStream(
                    new FileOutputStream(fileToExtractMessage));
            int i = 0;
            byte[] buffer = new byte[BUFFER_SIZE];
            i = bufferedInputStream.read(buffer, 0, BUFFER_SIZE);
            bufferedOutputStream.write(buffer, 0, i);
            bufferedOutputStream.close();
            byte[] mBuffer = new byte[mBUFFER_SIZE];
            do { // do while loop to read the message from the file containing the RSA decrypted
                 // message
                i = bufferedInputStream.read(mBuffer, 0, mBUFFER_SIZE);
                if (i <= 0) {
                    break;
                }
                bufferedOutputStream1.write(mBuffer, 0, i);
            } while (i == mBUFFER_SIZE);
            bufferedInputStream.close();
            bufferedOutputStream1.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * This method is used to read the file containing the RSA decrypted message and
     * return a byte array
     * 
     * @param inputFile  The file containing the RSA decrypted message
     * @param outputFIle The file to write the RSA decrypted message to
     * @param cipher     The cipher used to decrypt the message
     * @param yPrivKey   The private key of the receiver
     */
    public static void decryptRSA(String inputFile, String outputFIle, Cipher cipher, PrivateKey yPrivKey) {
        try { // try to read the file containing the RSA encrypted message and return a byte
              // array
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(inputFile));
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(outputFIle));
            cipher.init(Cipher.DECRYPT_MODE, yPrivKey);
            int BUFFER_SIZE = 128;
            byte[] buffer = new byte[BUFFER_SIZE];
            int i;
            byte[] doFinal; // byte array to hold the RSA decrypted message
            do {
                i = bufferedInputStream.read(buffer, 0, BUFFER_SIZE);
                byte[] updateBuffer = cipher.update(buffer, 0, BUFFER_SIZE);
                if (i <= 0) {
                    break;
                }
                doFinal = cipher.doFinal();
                bufferedOutputStream.write(doFinal);
            } while (i == BUFFER_SIZE);
            bufferedInputStream.close();
            bufferedOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * This method decrypts the AES encrypted message and writes the decrypted
     * message to a file
     * 
     * @param mdAddMsgFile        The file containing the RSA decrypted message
     * @param decryptedAddMsgFile The file to write the RSA decrypted message to
     * @param symmetricKey        The symmetric key used to encrypt the message
     * @param IV                  The initialization vector used to encrypt the
     *                            message
     */
    private static void decryptAES(String mdAddMsgFile, String decryptedAddMsgFile, String symmetricKey, String IV) {
        try {
            FileInputStream fileInputStream = new FileInputStream(mdAddMsgFile);
            FileOutputStream fileOutputStream = new FileOutputStream(decryptedAddMsgFile);
            SecretKeySpec symKey = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, symKey, new IvParameterSpec(IV.getBytes("UTF-8")));
            byte[] buff = new byte[1024]; // 1*1024
            for (int i = fileInputStream.read(buff); i > -1; i = fileInputStream.read(buff)) {
                fileOutputStream.write(cipher.update(buff, 0, i));
            }
            fileOutputStream.write(cipher.doFinal());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * This method is used to read the file containing the RSA and AES decrypted
     * message and return a byte array
     * 
     * @param f The file containing the RSA and AES decrypted message
     * @return The byte array containing the RSA and AES decrypted message
     */
    public static MessageDigest md(String f) {
        // reads file, calculates message digest and returns md which can be saved into
        // a byte array to be used later
        int BUFFER_SIZE = 32 * 1024;
        try { // try to read the file containing the RSA and AES decrypted message and return
              // a byte array
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(f));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            DigestInputStream in = new DigestInputStream(bufferedInputStream, md);
            int i;
            byte[] buffer = new byte[BUFFER_SIZE];
            do { // do while loop to read the file containing the RSA and AES decrypted message
                 // and return a byte array
                i = in.read(buffer, 0, BUFFER_SIZE);
                if (i <= 0) {
                    break;
                }
            } while (i == BUFFER_SIZE);
            md = in.getMessageDigest();
            in.close(); // file is read and the message digest exists in md
            return md;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * This method is used to write the bytes of the message digest to a file
     * 
     * @param bytesToWrite     The bytes of the message digest
     * @param fileToWriteBytes The file to write the bytes to
     */
    public static void writeBytesToFile(byte[] bytesToWrite, String fileToWriteBytes) throws Exception {
        try { // try to write the bytes of the message digest to a file
            BufferedOutputStream bout = new BufferedOutputStream(new FileOutputStream(fileToWriteBytes)); // outstream
                                                                                                          // buffer goes
                                                                                                          // to
                                                                                                          // FileOutputStream(name:"fileName.dd")
            bout.write(bytesToWrite, 0, bytesToWrite.length); // writes contents of bytesToWrite to
                                                              // FileOutputStream(name:"fileName.dd")
            bout.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * This method is used to convert a byte array to a hex string
     * 
     * @param hash The byte array to be converted to a hex string
     */
    public static void convertHex(byte[] hash) {
        // converts byte array to readable hex and displays
        System.out.println("digit digest (hash value):");
        for (int k = 0, j = 0; k < hash.length; k++, j++) {
            System.out.format("%2X ", hash[k]);
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
    }

    /**
     * This method is used to read the file containing the RSA and AES decrypted
     * message and return a byte array
     * 
     * @param inputFile The file containing the RSA and AES decrypted message
     * @return The byte array containing the RSA and AES decrypted message
     */
    public static byte[] readToFile(String inputFile) {
        try { // try to read the file containing the RSA and AES decrypted message and return
              // a byte array
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(inputFile)); // read
                                                                                                               // file
                                                                                                               // to
                                                                                                               // buffer
            int availableBytes = bufferedInputStream.available();
            int i;
            byte[] buffer = new byte[availableBytes];
            do {
                i = bufferedInputStream.read(buffer, 0, availableBytes);
                if (i <= 0) {
                    break;
                }
            } while (i == availableBytes);
            bufferedInputStream.close();
            // convertHex(buffer);
            return buffer;
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
            // return null;
        }
    }

    /**
     * This method is used to read the private key from a file and return a
     * PrivateKey object
     * 
     * @param keyFileName The file containing the private key
     * @return The PrivateKey object
     */
    public static PrivateKey readPrivKeyFromFile(String keyFileName) throws IOException {
        FileInputStream inputStream = new FileInputStream(keyFileName);
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream))) { // try
                                                                                                                  // to
                                                                                                                  // read
                                                                                                                  // the
                                                                                                                  // private
                                                                                                                  // key
                                                                                                                  // from
                                                                                                                  // a
                                                                                                                  // file
                                                                                                                  // and
                                                                                                                  // return
                                                                                                                  // a
                                                                                                                  // PrivateKey
                                                                                                                  // object
            BigInteger m = (BigInteger) objectInputStream.readObject();
            BigInteger e = (BigInteger) objectInputStream.readObject();
            // System.out.println("Read from " + keyFileName + ": modulus = " + m.toString()
            // + ", exponent = " + e.toString() + "\n");
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
    }

    /**
     * This method is used to read a symmetric key from a file and return a String
     * object containing the symmetric key
     * 
     * @param keyFileName The file containing the symmetric key
     * @return The String object containing the symmetric key
     */
    public static String readSymmetricKeyFromFile(String keyFileName) throws FileNotFoundException {
        try { // try to read the symmetric key from a file and return a String object
              // containing the symmetric key
            FileReader fileReader = new FileReader(keyFileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            return bufferedReader.readLine();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
