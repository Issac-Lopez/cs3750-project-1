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
    static byte[] SHA256M;

    // 1. keys copied to the Sender folder
    public static void main(String[] args) throws Exception {
        int sizeOfByteArray;
        //2. read the keys back from the files
        PublicKey pubKeyY = readPubKeyFromFile("YPublic.key");
        String symmetricKeyString = new String(Files.readAllBytes(Paths.get("symmetric.key")));
        symmetricKeyString = symmetricKeyString.substring(0,16); // used to eliminate invisible characters
        SecretKeySpec keyXY = new SecretKeySpec(symmetricKeyString.getBytes(StandardCharsets.UTF_8), "AES");
        //3. get the name of the message file
        Scanner input = new Scanner(System.in);
        System.out.println("Input the name of the message file, such as 'test.jpg': ");
        String messageFileName = input.nextLine();
        //4. use SHA256 to hash the message file and save the hash as message.dd
        //code for 4. was modified from https://www.tutorialspoint.com/java/io/bufferedoutputstream_write_byte.htm
        SHA256M = hashingMessage(messageFileName); //32 bytes long
        String messagedd = "message.dd";
        FileOutputStream fileOut = new FileOutputStream(new File(messagedd));
        // Use try-with-resources or close this "BufferedOutputStream" in a "finally" clause.
        BufferedOutputStream bufferedStream = new BufferedOutputStream(fileOut);
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
        //write(byte[] b, int off, int len)
        System.out.println("SHA256M LENGTH " + SHA256M.length );
        bufferedStream.write(SHA256M);
        System.out.println("Success with messagedd");
        //5.
        // calculate the AES Encryption of the SHA256(M) using keyXY and
        //save into a file named "message.add.msg" and display it as hexadecimal bytes
        sizeOfByteArray = 1024; //for AES encryption
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        // Use a dynamically-generated, random IV.
        cipher.init(Cipher.ENCRYPT_MODE, keyXY,new IvParameterSpec(IV.getBytes("UTF-8")));
        processFile(cipher,"message.dd", "message.add-msg",sizeOfByteArray, true, false);
        //append the message M read from the file specified in step 3 to the file message.add-msg "piece by piece"
        appendToFile(messageFileName);
        //6.
//        NOTE***************************************
//        For option 1 the RSA encryption is commented out in Sender.java because the encryption fails
//        on the last block and as a result it generates message.add-msg and cannot
//        generate message.rsacipher. For testing, I have been copying message.add-msg to
//        the receiver folder. The RSA decryption is also commented out in the Receiver.java
//        because I could not get it working in the sender.
//        **********************************************************
        //Calculate the RSA Encryption of
        sizeOfByteArray = 117; //for RSA encryption, block size 117
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
        SecureRandom random = new SecureRandom();
        cipher.init(Cipher.ENCRYPT_MODE, pubKeyY, random);
        processFile(cipher,"message.add-msg", "message.rsacipher",sizeOfByteArray, false, true);
        input.close();
        //bufferedStream.close(); //commented out was causing issues on the server, but not on IntelliJ
    }
//START OF HELPER METHODS--------------------------------------------------------------------------------

    //read key parameters from a file and generate the public key
    public static PublicKey readPubKeyFromFile(String keyFileName)
            throws IOException {
        InputStream in = new FileInputStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ": modulus = " + m.toString() + ", exponent = " + e.toString() + "\n");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
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
        //Use try-with-resources or close this "BufferedInputStream" in a "finally" clause.
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // Use try-with-resources or close this "DigestInputStream" in a "finally" clause.
//        try {
//            DigestInputStream in = new DigestInputStream(file, md);
//            // read the file and update the hash calculation
//            while (in.read() != -1) ;
//            // get the hash value as byte array
//            return md.digest();
//        } finally {
//            file.close();
//        }
        DigestInputStream in = new DigestInputStream(file, md);
        int i;
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            i = in.read(buffer, 0, BUFFER_SIZE);
        } while (i == BUFFER_SIZE);
        md = in.getMessageDigest();
        in.close();
        FileOutputStream output = new FileOutputStream("message.dd");
        byte[] hash = md.digest();
        System.out.println("The SHA256(M):"); // for testing
        for (byte b : hash) {
            System.out.format("%02x", b);
        }
        output.close();
        System.out.println("");
        return hash;
    }
    //the method processFile is derived from  https://www.novixys.com/blog/java-aes-example/
    private static void processFile(Cipher ci,String inFile,String outFile, int sizeOfByteArray, boolean doingAESofSHA256Hash, boolean doingRSA) //added parameter sizeOfByteArray, doingAESofSHA256Hast
            throws java.io.IOException {
        // Use try-with-resources or close streams in "finally" clause.
//        try (FileInputStream in = new FileInputStream(inFile);
//             FileOutputStream out = new FileOutputStream(outFile)) {
//            byte[] ibuf = new byte[sizeOfByteArray];
//            int len;
//            while ((len = in.read(ibuf)) != -1) {
//                if (doingAESofSHA256Hash) {
//                    //if doing AES of SHA256 hash, then pad the last block with zeros
//                    if (len < sizeOfByteArray) {
//                        ibuf = padLastBlock(ibuf, len);
//                    }
//                }
//                if (doingRSA) {
//                    //if doing RSA, then pad the last block with zeros
//                    if (len < sizeOfByteArray) {
//                        ibuf = padLastBlock(ibuf, len);
//                    }
//                }
//                byte[] obuf = ci.update(ibuf, 0, len);
//                if ( obuf != null ) out.write(obuf);
//            }
//            byte[] obuf = ci.doFinal();
//            if ( obuf != null ) out.write(obuf);
//        }
        try (FileInputStream in = new FileInputStream(inFile); FileOutputStream out = new FileOutputStream(outFile)) {
            File fileToCheckSize = new File(inFile); //added line
            long sizeOfFile = fileToCheckSize.length(); //added line, gets file size in bytes
            System.out.println("Size of incoming file " + sizeOfFile); //added line
            long counter = 0;
            byte[] ibuf = new byte[sizeOfByteArray];
            int len;
        while ((len = in.read(ibuf)) != -1) {
                counter += len;
                System.out.println("Counter " + counter);
                if (doingAESofSHA256Hash) {
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
                } else if (doingRSA) {
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
                } else {
                    byte[] obuf = ci.update(ibuf, 0, len);
                    if ( obuf != null ) out.write(obuf);
                }
            }
        }
    }
    //appendToFile derived from https://stackoverflow.com/questions/32208792/how-do-i-use-buffered-streams-to-append-to-a-file-in-java
    //this method appends the encrypted file to the encrypted file
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