//Name
//CS3750
//PROJECT 1

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;

public class Receiver {
    private static int BUFFER_SIZE = 32 * 1024;
    static String IV = "AAAAAAAAAAAAAAAA";
    static byte[] SHA256MfromDecryption;
    public Receiver() throws IOException {
    }
    //1. keys copied to the Sender folder
    public static void main(String[] args) throws Exception {
        int sizeOfByteArray;
        //2. read the keys back from the files
        PrivateKey privateKeyY = readPrivKeyFromFile("YPrivate.key");
        String symmetricKeyString = new String(Files.readAllBytes(Paths.get("symmetric.key")));
        symmetricKeyString = symmetricKeyString.substring(0,16); //substring used to eliminate invisible characters
        SecretKeySpec keyXY = new SecretKeySpec(symmetricKeyString.getBytes("UTF-8"), "AES");
        //3. get the name of the message file
        Scanner input = new Scanner(System.in);
        System.out.println("Input the name of the message file such as 'test.jpg': ");
        String messageFileName = input.nextLine();
        //4. Perform the RSA decryption
        sizeOfByteArray = 128; //for RSA decryption, block size is 128
        Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
        cipher2.init(Cipher.DECRYPT_MODE, privateKeyY);
        processFile(cipher2,"message.rsacipher", "message.add-msg",sizeOfByteArray, false, true);
        // 5.get the AES encrypted hash file along with the message file from message.add-msg
        getHashAndMessageFiles("message.add-msg","hashAESencrypted.dd", messageFileName);
        // calculate the AES Decryption of the SHA256(M) using keyXY and
        //save into a file named "message.dd" and display it as hexadecimal bytes
        sizeOfByteArray = 1024; //for AES decryption

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, keyXY,new IvParameterSpec(IV.getBytes("UTF-8")));
        processFile(cipher,"hashAESencrypted.dd", "message.dd",sizeOfByteArray, true, false);
        // 6. use SHA256 to hash the message file and save the hash as message.dd
        //code was modified from https://www.tutorialspoint.com/java/io/bufferedoutputstream_write_byte.htm
        SHA256MfromDecryption = hashingMessage(messageFileName); //32 bytes long
        byte[] SHA256MfromEncryption = getHashMadeBySender("message.dd");
        boolean areHashValuesEqual = Arrays.equals(SHA256MfromEncryption, SHA256MfromDecryption);
        if(areHashValuesEqual) {
            System.out.println("DIGITAL DIGEST PASSES THE AUTHENTICATION CHECK");
        } else {
            System.out.println("DIGITAL DIGEST DID NOT PASS THE AUTHENTICATION CHECK");
        }
    }
    // START OF HELPER METHODS ---------------------------------------------------------------
    // read key parameters from a file and generate the public key
    // read key parameters from a file and generate the private key
    public static PrivateKey readPrivKeyFromFile(String keyFileName) throws IOException {
        InputStream in = new FileInputStream(keyFileName);
        //Sender.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ": modulus = " + m.toString() + ", exponent = " + e.toString() + "\n");
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey key = factory.generatePrivate(keySpec);
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
        //PrintWriter output = new PrintWriter("message.dd"); //if need be switch to FileOutputStream
        byte[] hash = md.digest();
        System.out.println("The SHA256(M):");
        for (int k=0, j=0; k<hash.length; k++, j++) {
            //output.format("%02X ", hash[k]); //to latter save to message.dd
            System.out.format("%2X ", hash[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        //output.close();
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
                    System.out.println("The SHA256(M) Decrypted with AES is:");
                    for (int k=0, j=0; k<obuf.length; k++, j++) {
                        System.out.format("%2X ", obuf[k]) ;
                        if (j >= 15) {
                            System.out.println("");
                            j=-1;
                        }
                    }
                }
                if(doingRSA) {
                    byte[] obuf = ci.doFinal(ibuf, 0, len);
                    if ( obuf != null ) out.write(obuf);
                }
            }
            System.out.println("The leftovers being processed are " + (counter - sizeOfFile)); //added line
            //byte[] lastPartition = new byte[(counter - sizeOfFile)];
            if (doingAESofSHA256Hash) {
                byte[] obuf = ci.doFinal();
                if ( obuf != null ) out.write(obuf);
            }
        }
    }
    static private void getHashAndMessageFiles(String inFile,String toHashFile, String toMessageFile)
            throws java.io.IOException
    {
        //devived from https://stackoverflow.com/questions/18811608/how-to-read-fixed-number-of-bytes-from-a-file-in-a-loop-in-java
        //as well as https://stackoverflow.com/questions/32208792/how-do-i-use-buffered-streams-to-append-to-a-file-in-java
        try (FileInputStream in = new FileInputStream(inFile);
             FileOutputStream out = new FileOutputStream(toHashFile))
        {
            //write the hash file
            byte[] result = new byte[32]; //to get hash values
            in.read(result, 0, 32);//read(byte array, offset, how many bytes to read), fills byte array result
            out.write(result, 0, 32);
            //write the message file
            FileOutputStream out2 = new FileOutputStream(toMessageFile);
            byte[] buf2 = new byte[1024];
            int len;
            while ((len = in.read(buf2)) != -1) {
                out2.write(buf2, 0, len);
            }
            out.flush();
        }
    }
    static private byte[] getHashMadeBySender(String inFile)
            throws java.io.IOException
    {
        //devived from https://stackoverflow.com/questions/18811608/how-to-read-fixed-number-of-bytes-from-a-file-in-a-loop-in-java
        //as well as https://stackoverflow.com/questions/32208792/how-do-i-use-buffered-streams-to-append-to-a-file-in-java
        try (FileInputStream in = new FileInputStream(inFile)) {
            //write the hash file
            byte[] result = new byte[32]; //to get hash values
            in.read(result, 0, 32);//read(byte array, offset, how many bytes to read), fills byte array result
            return result;
        }
    }
}