//Name
//CS3750
//PROJECT 1

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
public class Sender {
    private static int BUFFER_SIZE = 32 * 1024;
    static String IV = "AAAAAAAAAAAAAAAA";
    static byte[] SHA256M;
    public Sender() throws IOException {
    }
    // 1. keys copied to the Sender folder
    public static void main(String[] args) throws Exception {
        int sizeOfByteArray;
        //2. read the keys back from the files
        PublicKey pubKeyY = readPubKeyFromFile("YPublic.key");
        String symmetricKeyString = new String(Files.readAllBytes(Paths.get("symmetric.key")));
        symmetricKeyString = symmetricKeyString.substring(0,16); // used to eliminate invisible characters
        SecretKeySpec keyXY = new SecretKeySpec(symmetricKeyString.getBytes("UTF-8"), "AES");
        //3. get the name of the message file
        Scanner input = new Scanner(System.in);
        System.out.println("Input the name of the message file, such as 'test.jpg': ");
        String messageFileName = input.nextLine();
        //4. use SHA256 to hash the message file and save the hash as message.dd
        //code for 4. was modified from https://www.tutorialspoint.com/java/io/bufferedoutputstream_write_byte.htm
        SHA256M = hashingMessage(messageFileName); //32 bytes long
        String messagedd = "message.dd";
        FileOutputStream fileOut = new FileOutputStream(new File(messagedd));
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
            if(bufferedStream!=null)
                bufferedStream.flush();
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
        cipher.init(Cipher.ENCRYPT_MODE, keyXY,new IvParameterSpec(IV.getBytes("UTF-8")));
        processFile(cipher,"message.dd", "message.add-msg",sizeOfByteArray, true, false);
        //append the message M read from the file specified in step 3 to the file message.add-msg "piece by piece"
        appendToFile(messageFileName,"message.add-msg");
        //6.
//        NOTE***************************************
//        For option 1 the RSA encryption is commented out in Sender.java because the encryption fails
//        on the last block and as a result it generates message.add-msg and and cannot
//        generate message.rsacipher. For testing I have been copying message.add-msg to
//        the receiver folder. The RSA decryption is also commented out in the Receiver.java
//        because I could not get it working in the sender.
//        **********************************************************
        //Calculate the RSA Encryption of
        sizeOfByteArray = 117; //for RSA encryption, block size 117
        Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
        SecureRandom random = new SecureRandom();
        cipher2.init(Cipher.ENCRYPT_MODE, pubKeyY, random);
        processFile(cipher2,"message.add-msg", "message.rsacipher",sizeOfByteArray, false, true);
        input.close();
        //bufferedStream.close(); //commented out was causing issues on the server, but not on IntelliJ
    }
//START OF HELPER METHODS--------------------------------------------------------------------------------

    //read key parameters from a file and generate the public key
    public static PublicKey readPubKeyFromFile(String keyFileName)
            throws IOException {
        InputStream in = new FileInputStream(keyFileName);
        //Sender.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ": modulus = " + m.toString() + ", exponent = " + e.toString() + "\n");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
    public static byte[] hashingMessage(String f) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, md);
        int i;
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            i = in.read(buffer, 0, BUFFER_SIZE);
        } while (i == BUFFER_SIZE);
        md = in.getMessageDigest();
        in.close();
        PrintWriter output = new PrintWriter("message.dd"); //if need be switch to FileOutputStream
        byte[] hash = md.digest();
        System.out.println("The SHA256(M):");
        for (int k=0, j=0; k<hash.length; k++, j++) {
            output.format("%02X ", hash[k]); //to latter save to message.dd
            System.out.format("%2X ", hash[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        output.close();
        System.out.println("");
        return hash;
    }
    //the method processFile is derived from  https://www.novixys.com/blog/java-aes-example/
    static private void processFile(Cipher ci,String inFile,String outFile, int sizeOfByteArray, boolean doingAESofSHA256Hash, boolean doingRSA) //added parameter sizeOfByteArray, doingAESofSHA256Hast
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        try (FileInputStream in = new FileInputStream(inFile);
             FileOutputStream out = new FileOutputStream(outFile))
        {
            File fileToCheckSize = new File(inFile); //added line
            long sizeOfFile = fileToCheckSize.length(); //added line, gets file size in bytes
            System.out.println("Size of incoming file " + sizeOfFile); //added line
            long counter = 0; //added line
            byte[] ibuf = new byte[sizeOfByteArray];
            int len;
            while ((len = in.read(ibuf)) != -1) {
                counter = counter + sizeOfByteArray; //added line
                //System.out.println("The current counter is " + counter); //added line
                if(doingAESofSHA256Hash) {
                    byte[] obuf = ci.update(ibuf, 0, len);
                    if ( obuf != null ) out.write(obuf);
                    System.out.println("The SHA256(M) Encrypted with AES is:");
                    for (int k=0, j=0; k<obuf.length; k++, j++) {
                        System.out.format("%2X ", obuf[k]) ;
                        if (j >= 15) {
                            System.out.println("");
                            j=-1;
                        }
                    }
                }
                if(doingRSA) {
                    //last block is not full
                    if((sizeOfFile - counter) < 0) {
                        int size = (int) (counter - sizeOfFile); //gets remaining size of last block
                        byte[] lastBlock = Arrays.copyOf(ibuf, size);
                        System.out.println("THE LAST BLOCK: ");
                        for (int k=0, j=0; k<lastBlock.length; k++, j++) {
                            System.out.format("%2X ", lastBlock[k]) ;
                            if (j >= 15) {
                                System.out.println("");
                                j=-1;
                            }
                        }
                        byte[] obuf = ci.doFinal(lastBlock);
                        if ( obuf != null ) out.write(obuf);
                    }
                    //not the last block
                    if((sizeOfFile - counter) >= 0) {
                        byte[] obuf = ci.doFinal(ibuf);
                        if ( obuf != null ) out.write(obuf);
                    }
                }
            }
            //System.out.println("The leftovers being processed are " + (counter - sizeOfFile)); //added line
            //byte[] lastPartition = new byte[(counter - sizeOfFile)];
            if (doingAESofSHA256Hash) {
                byte[] obuf = ci.doFinal();
                if ( obuf != null ) out.write(obuf);
            }
        }
    }
    //appendToFile derived from https://stackoverflow.com/questions/32208792/how-do-i-use-buffered-streams-to-append-to-a-file-in-java
    static private void appendToFile(String inFile,String outFile)
            throws java.io.IOException
    {
        try (FileInputStream in = new FileInputStream(inFile);
             FileOutputStream out = new FileOutputStream(outFile,true))
        {
            byte[] buf = new byte[1024];
            int len;
            while ((len = in.read(buf)) != -1) {
                out.write(buf, 0, len);
            }
            out.flush();
        }
    }
}