//Name
//CS3750
//PROJECT 1
package project1.Sender;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Scanner;
import javax.crypto.Cipher;
public class Sender {
    private static int BUFFER_SIZE = 32 * 1024;
    static String IV = "AAAAAAAAAAAAAAAA";
    static byte[] SHA256M; // SHA256 of the message
    static String messageDigitalDigest = "message.dd";

    public static void main(String[] args) throws Exception {
        int sizeOfByteArray;
        // read the keys back from the key files
        PublicKey pubKeyY = readPubKeyFromFile("YPublic.key");
        String symmetricKeyString = new String(Files.readAllBytes(Paths.get("./symmetric.key")));
        symmetricKeyString = symmetricKeyString.substring(0,16); // used to eliminate invisible characters
        SecretKeySpec keyXY = new SecretKeySpec(symmetricKeyString.getBytes(StandardCharsets.UTF_8), "AES");
        // get the name of the message file
        Scanner input = new Scanner(System.in);
        System.out.println("Input the name of the message file: "); // this is the file(M) that will be encrypted
        String messageFileName = input.nextLine();
        // use SHA256 to hash the message file and save the hash as message.dd
        SHA256M = hashingMessage(messageFileName); //32 bytes long
        BufferedOutputStream bufferedStream = new BufferedOutputStream(new FileOutputStream(messageDigitalDigest));
        try {
            // write byte array to the output stream
            bufferedStream.write(SHA256M, 0, SHA256M.length);
            // flush the bytes to be written out
            bufferedStream.flush();
        } catch(IOException e) {
            // if any IOError occurs
            e.printStackTrace();
        } finally {
            // releases any system resources associated with the stream
            bufferedStream.close();
        }
        System.out.println("Do you want to invert the 1st byte in SHA256(M)? (Y or N) ");
        String invert = input.nextLine();
        if (invert.equals("Y")) {
            SHA256M[0] = (byte) ~SHA256M[0];
        } else if (invert.equals("N")) {
            System.out.println("The 1st byte in SHA256(M) will not be inverted");
        } else {
            System.out.println("Invalid input");
        }

        bufferedStream.close();
        // calculate the AES Encryption of the SHA256(M) using symmetric key and
        // save into a file named "message.add-msg" and display it in hexadecimal bytes
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, keyXY,new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8)));
        byte[] encryptedSHA256M = cipher.doFinal(SHA256M);
        // save aes cipher text into a file named "message.add-msg"
        BufferedOutputStream bufferedStream2 = new BufferedOutputStream(new FileOutputStream("message.add-msg"));
        bufferedStream2.write(cipher.doFinal(SHA256M));
        // display in hexadecimal bytes
        System.out.println("The AES Encryption of the SHA256(M) is saved in a file named \"message.add-msg\" and displayed in hexadecimal bytes: ");
        for (byte b : encryptedSHA256M) {
            System.out.printf("%02X ", b);
        }
        //append the message M read from the file specified in step 3 to the file message.add-msg "piece by piece"
        appendToFile(messageFileName);
        //Calculate the RSA Encryption of the SHA256(M) using public key Y reading the file message.add-msg
        // and save into a file named "message.rsacipher" and display it in hexadecimal bytes
        byte[] rsaCipher = rsaEncryption(messageFileName, pubKeyY);
        BufferedOutputStream bufferedStream3 = new BufferedOutputStream(new FileOutputStream("message.rsacipher"));
        bufferedStream3.write(rsaCipher);
        input.close();
        bufferedStream.close(); //commented out was causing issues on the server, but not on IntelliJ
    }

    private static byte[] rsaEncryption(String messageFileName, PublicKey pubKeyY) {
        byte[] rsaCipher = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
            SecureRandom random = new SecureRandom();
            cipher.init(Cipher.ENCRYPT_MODE, pubKeyY, random);
            rsaCipher = cipher.doFinal(SHA256M);
            System.out.println();
            // save rsa cipher text into a file named "message.rsacipher"
            BufferedOutputStream bufferedStream3 = new BufferedOutputStream(new FileOutputStream("message.rsacipher"));
            bufferedStream3.write(rsaCipher);
            // display in hexadecimal bytes
            System.out.println("The RSA Encryption of the SHA256(M) is saved in a file named \"message.rsacipher\" and displayed in hexadecimal bytes: ");
            for (byte b : rsaCipher) {
                System.out.printf("%02X ", b);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rsaCipher;
    }
//START OF HELPER METHODS--------------------------------------------------------------------------------

    //read key parameters from a file and generate the public key
    public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {
        InputStream in = new FileInputStream(keyFileName);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger n = (BigInteger) oin.readObject();
            BigInteger d = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ": modulus = " + n.toString() + ", exponent = " + d.toString() + "\n");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(n, d);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally { // this is necessary because oin is a CheckedInputStream
            oin.close(); // close the stream
        }
    }
    // hashing the message file
    public static byte[] hashingMessage(String f) throws Exception {
//        BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
//        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            BufferedInputStream fis = new BufferedInputStream(new FileInputStream(f));
            byte[] dataBytes = new byte[BUFFER_SIZE];
            int nread = 0;
            while ((nread = fis.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, nread);
            }
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        }
//        byte[] buffer = new byte[BUFFER_SIZE];
//        do {
//            i = in.read(buffer, 0, BUFFER_SIZE);
//        } while (i == BUFFER_SIZE);
//        md = in.getMessageDigest();
//        in.close();
//        FileOutputStream output = new FileOutputStream(messageDigitalDigest);
//        byte[] hash = md.digest();
//        System.out.println("The SHA256(M):");
//        for (byte b : hash) {
//            System.out.format("%02x", b);
//        }
//        output.close();
//        System.out.println("");
//        return hash;
    }
    private static void processFile(Cipher ci, int sizeOfByteArray) throws java.io.IOException {
        try (FileInputStream in = new FileInputStream("message.add-msg"); FileOutputStream out = new FileOutputStream("message.rsacipher")) {
            File fileToCheckSize = new File("message.add-msg"); //added line
            long sizeOfFile = fileToCheckSize.length(); //added line, gets file size in bytes
            System.out.println("Size of incoming file " + sizeOfFile); //added line
            long counter = 0;
            byte[] ibuf = new byte[sizeOfByteArray];
            int len;
        while ((len = in.read(ibuf)) != -1) {
                counter += len;
                System.out.println("Counter " + counter);
                if (false) {
                    if (counter == sizeOfFile) {
                        System.out.println("Last block of AES of SHA256 hash");
                        //if last block of AES of SHA256 hash
                        //pad the last block with 0's
                        byte[] paddedIbuf = new byte[1024];
                        System.arraycopy(ibuf, 0, paddedIbuf, 0, ibuf.length);
                        byte[] obuf = ci.update(paddedIbuf);
                        if ( obuf != null ) out.write(obuf);
                    } else {
                        System.out.println("Not last block of AES of SHA256 hash");
                        byte[] obuf = ci.update(ibuf, 0, len);
                        if ( obuf != null ) out.write(obuf);
                    }
                } else {
                    if (counter == sizeOfFile) {
                        System.out.println("Last block of RSA");
                        //if last block of RSA
                        //pad the last block with 0's
                        byte[] paddedIbuf = new byte[117];
                        System.arraycopy(ibuf, 0, paddedIbuf, 0, ibuf.length);
                        byte[] obuf = ci.update(paddedIbuf);
                        if ( obuf != null ) out.write(obuf);
                    } else {
                        System.out.println("Not last block of RSA");
                        byte[] obuf = ci.update(ibuf, 0, len);
                        if ( obuf != null ) out.write(obuf);
                    }
                }
            }
        }
    }
    private static void appendToFile(String inFile) throws java.io.IOException {
        try (FileInputStream in = new FileInputStream(inFile);
             FileOutputStream out = new FileOutputStream("message.add-msg",true)) {
            byte[] buf = new byte[1024];
            int len;
            while ((len = in.read(buf)) != -1) {
                out.write(buf, 0, len);
            }
            out.flush();
        }
    }
}