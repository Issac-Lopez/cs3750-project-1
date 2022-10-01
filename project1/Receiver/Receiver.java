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
    //1. keys copied to the Sender folder
    public static void main(String[] args) throws Exception {
        int sizeOfByteArray;
        //2. read the keys back from the files
        PrivateKey privateKeyY = readPrivKeyFromFile("YPrivate.key");
        String symmetricKeyString = new String(Files.readAllBytes(Paths.get("symmetric.key")));
        symmetricKeyString = symmetricKeyString.substring(0,16); //substring used to eliminate invisible characters
        // Replace charset name argument with StandardCharsets.UTF_8
        byte[] symmetricKey = symmetricKeyString.getBytes("UTF-8");
        SecretKeySpec keyXY = new SecretKeySpec(symmetricKeyString.getBytes("UTF-8"), "AES");
        //3. get the name of the message file
        Scanner input = new Scanner(System.in);
        System.out.println("Input the name of the message file such as 'test.jpg': ");
        String messageFileName = input.nextLine();
        //4. Perform the RSA decryption
        sizeOfByteArray = 128; //for RSA decryption, block size is 128
        // Use secure mode and padding scheme
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "SunJCE");
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
    // Sender.class.getResourceAsStream(keyFileName);
    // assume usrInput is a string conating user input regarding the file name of the message file
    // buffereredinput ... msgfile = new bufferedinputstream(new fileinputstream(usrinput));
    // create byte array  whose size is BLOCK_SIZE (117 bytes OR 1600 kb)
    // assuming the array is named plaintext[]
    // int numBytesRead = msgfile.read(plaintext, 0, BLOCK_SIZE);
    // if (numBytesRead == -1) break;
    // if nunBytesRead is less than plaintext.length but still greater than 0,
    // then create a new byte array of size numBytesRead and copy the contents of plaintext
    // to the new array
    // but loop must terminate after completing the last block in current iteration

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
            // mmediately return this expression instead of assigning it to the temporary variable "key"
            return factory.generatePrivate(keySpec);
        } catch (Exception e) {
            // Define and throw a dedicated exception instead of using a generic one.
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
    public static byte[] hashingMessage(String f) throws Exception { // Define and throw a dedicated exception instead of using a generic one.
        // Use try-with-resources or close this "BufferedInputStream" in a "finally" clause
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(f))) {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] dataBytes = new byte[BUFFER_SIZE];
            int bytesRead = 0;
            while ((bytesRead = bufferedInputStream.read(dataBytes)) != -1) {
                messageDigest.update(dataBytes, 0, bytesRead);
            }
            byte[] hash = messageDigest.digest();
            //code was modified from https://www.tutorialspoint.com/java/io/bufferedoutputstream_write_byte.htm
            try (BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream("message.dd"))) {
                bufferedOutputStream.write(hash);
            }
            return hash;
        }
        //PrintWriter output = new PrintWriter("message.dd"); //if need be switch to FileOutputStream
        byte[] hash = md.digest();
        System.out.println("The SHA256(M):");
        for (int i = 0; i < hash.length; i++) {
            System.out.format("%02x", hash[i]);
        }
        //output.close();
        System.out.println("");
        return hash;
    }
    //the method processFile is derived from  https://www.novixys.com/blog/java-aes-example/
    private static void processFile(Cipher ci,String inFile,String outFile, int sizeOfByteArray, boolean doingAESofSHA256Hash, boolean doingRSA) //added parameter sizeOfByteArray, doingAESofSHA256Hast
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        // Use try-with-resources or close streams in a "finally" clause
        try (FileInputStream fis = new FileInputStream(inFile);
             FileOutputStream fos = new FileOutputStream(outFile);
             CipherOutputStream cos = new CipherOutputStream(fos, ci)) {
            byte[] ibuf = new byte[sizeOfByteArray];
            int len;
            while ((len = fis.read(ibuf)) != -1) {
                if(doingAESofSHA256Hash) {
                    if(len < sizeOfByteArray) {
                        byte[] temp = new byte[len];
                        System.arraycopy(ibuf, 0, temp, 0, len);
                        cos.write(temp);
                    } else {
                        cos.write(ibuf, 0, len);
                    }
                } else {
                    cos.write(ibuf, 0, len);
                }
            }
        }
         finally {
             if (fis != null) fis.close();
             if (fos != null) fos.close();
             if (cos != null) cos.close();
         }
            System.out.println("The leftovers being processed are " + (counter - sizeOfFile)); //added line
            //byte[] lastPartition = new byte[(counter - sizeOfFile)];
            if (doingAESofSHA256Hash) {
                byte[] obuf = ci.doFinal();
                if ( obuf != null ) out.write(obuf);
            }
        }
    }
    private static void getHashAndMessageFiles(String inFile,String toHashFile, String toMessageFile)
            throws java.io.IOException
    {
        //devived from https://stackoverflow.com/questions/18811608/how-to-read-fixed-number-of-bytes-from-a-file-in-a-loop-in-java
        //as well as https://stackoverflow.com/questions/32208792/how-do-i-use-buffered-streams-to-append-to-a-file-in-java
        // Use try-with-resources or close this "BufferedInputStream" in a "finally" clause
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(inFile))) {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] dataBytes = new byte[BUFFER_SIZE];
            int bytesRead = 0;
            while ((bytesRead = bufferedInputStream.read(dataBytes)) != -1) {
                messageDigest.update(dataBytes, 0, bytesRead);
            }
            byte[] hash = messageDigest.digest();
            //code was modified from https://www.tutorialspoint.com/java/io/bufferedoutputstream_write_byte.htm
            try (BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(toHashFile))) {
                bufferedOutputStream.write(hash);
            }
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
    }
    private static byte[] getHashMadeBySender(String inFile)
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