import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
/**
 * This class is used to encrypt the message using the symmetric key and the
 * public key of the receiver.
 */
public class Sender {
    public static void main(String[] args) throws Exception {
        String IV = "AAAAAAAAAAAAAAAA"; // 16 bytes
        String symmetricKeyFileName = "symmetric.key"; // symmetric key file name
        String YPublicKeyFile = "YPublic.key"; // The public key of the receiver
        String fileToWriteDigest = "message.dd"; // The file that will contain the digest of the message
        SecureRandom random = new SecureRandom(); // Secure random number generator
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // RSA cipher
        String symmetricKey = readSymmetricKeyFromFile(symmetricKeyFileName); //Kxy
        PublicKey yPubKey = readPubKeyFromFile(YPublicKeyFile); //Ky+
        Scanner scn = new Scanner(System.in); // Scanner to read the message from the user
        System.out.println("==================================================================");
        System.out.println("== Input the name of the message file you would like to encrypt ==");
        System.out.println("==================================================================");
        System.out.println();
        String messageFileName = scn.nextLine(); // The name of the message file
        try { // Encrypt the message using the symmetric key and the public key of the receiver (Ky+)
            // Read the message from the file
            MessageDigest md = md(messageFileName); //H(m)
            assert md != null; // Check if the message digest is null
            byte[] SHA256MHash = md.digest(); // H(m)
            // invert the first byte in hash form user input
            System.out.println("===================================================================");
            System.out.println("===== Do you want to invert the 1st byte in SHA256(M)? (Y or N) ===");
            System.out.println("===================================================================");
            System.out.println();
            String invert = scn.nextLine();
            System.out.println();
            if(invert.equals("yes") || invert.equals("Yes") || invert.equals("Y") || invert.equals("y") || invert.equals("YES")){ // If the user wants to invert the first byte
                toHexadecimal(SHA256MHash); // Convert the hash to hexadecimal
                SHA256MHash[0] = (byte) ~SHA256MHash[0]; // Invert the first byte
                //System.out.println(SHA256MHash);
                System.out.println("");
                writeToFile(SHA256MHash, fileToWriteDigest); // Write the digest to the file
                System.out.println("***** INVERTED MESSAGE DIGEST *****");
                byte[] msgDigest = readToFile(fileToWriteDigest);
                toHexadecimal(msgDigest);
                System.out.println("");
            } else if (invert.equals("no") || invert.equals("No") || invert.equals("n") || invert.equals("N") || invert.equals("NO")){ // If the user does not want to invert the first byte
                System.out.println("***** The 1st byte in SHA256(M) will not be inverted *****");
                //System.out.println(SHA256MHash);
                System.out.println("");
                writeToFile(SHA256MHash, fileToWriteDigest);
                byte[] messageDigest = readToFile(fileToWriteDigest); // Read the digest from the file
                toHexadecimal(messageDigest);
            } else { // If the user does not input a valid answer
                System.out.println("Whoops! Looks like you entered an invalid input!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        // AES encryption of message digest using symmetric key Kxy and IV = AAAAAAAAAAAAAAAA (16 bytes) and write to file message.add-msg
        encryptAES(symmetricKey, IV); // AES(Kxy, IV, H(m))
        appendToFile(messageFileName, "message.add-msg"); // Append the message to the message digest
        // RSA encryption of symmetric key Kxy using public key Ky+ and write to file message.rsacipher (RSA/ECB/PKCS1Padding)
        encryptRSA("message.add-msg", "message.rsacipher", cipher, random, yPubKey); // RSA(Ky+, Kxy)
        System.out.println("==========================================================================================================");
        System.out.println("RSA encryption of symmetric key Kxy using public key Ky+ and wrote to file message.rsacipher successfully!");
        System.out.println("==========================================================================================================");
    }
    /**
     * This method reads the symmetric key from the file symmetric.key
     * @param inputFile the file to read from
     * @param appendedFile the file to append to
     */
    public static void appendToFile(String inputFile, String appendedFile) {
        try { // Try to append the message to the message digest
            int BUFFER_SIZE = 1024;
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(inputFile));
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(appendedFile, true));
            int i;
            byte[] buffer = new byte[BUFFER_SIZE];
            do { // Read the message from the file
                i = bufferedInputStream.read(buffer, 0, BUFFER_SIZE);
                if(i<=0){ // If the message is empty
                    break;
                }
                bufferedOutputStream.write(buffer, 0, i);
            } while (i == BUFFER_SIZE); // While the message is not empty
            bufferedInputStream.close();
            bufferedOutputStream.close();
        }catch (Exception e){
            e.printStackTrace();
        } finally { // If the message is empty
            System.out.println("Message has been successfully appended to file: " + appendedFile);
        }
    }
    /**
     * RSA encryption of symmetric key Kxy using public key Ky+ and write to file message.rsacipher (RSA/ECB/PKCS1Padding)
     * @param inputFile file to read from
     * @param outputFile file to write to
     * @param cipher cipher to use
     * @param random random number generator
     * @param yPubKey public key Ky+
     */
    public static void encryptRSA(String inputFile, String outputFile, Cipher cipher, SecureRandom random, PublicKey yPubKey) {
        try { // RSA(Ky+, Kxy)
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(inputFile));
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
            cipher.init(Cipher.ENCRYPT_MODE, yPubKey, random); // RSA(Ky+, Kxy)
            int BUFFER_SIZE = 117; // 128 - 11
            byte[] buffer = new byte[BUFFER_SIZE];
            int i = 0;
            do { // Read the file in 117 byte chunks
                i = bufferedInputStream.read(buffer, 0, BUFFER_SIZE);
                if (i < 117) { // If the file is less than 117 bytes
                    byte[] cipherText = new byte[i];
                    i = bufferedInputStream.read(buffer, 0, i);
                    bufferedOutputStream.write(cipher.doFinal(buffer, 0, cipherText.length));
                    if(i <= 0){ // If the file is less than 117 bytes
                        break;
                    }
                }
                bufferedOutputStream.write(cipher.doFinal(buffer, 0, BUFFER_SIZE));
            } while (i == BUFFER_SIZE); // While the file is greater than 117 bytes
            bufferedInputStream.close();
            bufferedOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /**
     * AES encryption of message digest using symmetric key, Kxy, and IV then write to file message.add-msg
     * @param symmetricKey symmetric key
     * @param IV initialization vector
     */
    private static void encryptAES(String symmetricKey, String IV) {
        try { // AES(Kxy, IV, H(m))
            FileInputStream fileInputStream = new FileInputStream("message.dd");
            FileOutputStream fileOutputStream = new FileOutputStream("message.add-msg");
            SecretKeySpec symKey = new SecretKeySpec(symmetricKey.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, symKey, new IvParameterSpec(IV.getBytes(StandardCharsets.UTF_8)));
            byte[] inBuffer = new byte[2048];
            for (int i = fileInputStream.read(inBuffer); i > 0; i = fileInputStream.read(inBuffer)) { // Read the file
                byte[] outBuffer = cipher.update(inBuffer, 0, i); // Encrypt the file
                fileOutputStream.write(outBuffer); // Write the encrypted file
            }
            byte[] outBuffer = cipher.doFinal(); // Encrypt the file
            fileOutputStream.write(outBuffer); // Write the encrypted file
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /**
     * Reads the file, calculates message digest and returns md which can be saved into a byte array for later use.
     * @param f the file to read from
     * @return message digest in byte array format
     */
    public static MessageDigest md(String f) {
        try { // Try to read the file
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(f));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            DigestInputStream in = new DigestInputStream(bufferedInputStream, md);
            int BUFFER_SIZE = 32 * 1024; // 32KB
            int i;
            byte[] buffer = new byte[BUFFER_SIZE]; // 32KB buffer
            do { // Read through the file
                i = in.read(buffer, 0, BUFFER_SIZE);
                if (i <= 0) { // If the end of the file is reached
                    break;
                }
            } while (i == BUFFER_SIZE); // If the file is larger than the buffer size, read the file again
            md = in.getMessageDigest(); // Get the message digest
            in.close();
            return md; // Return the message digest
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * Converts byte array to hexadecimal and displays it
     * @param in byte array to convert
     */
    public static void toHexadecimal(byte[] in) {
        for (int k = 0, j = 0; k < in.length; k++, j++) { // k is the index for in, j is the index for out
            System.out.format("%2X ", in[k]);
            if (j >= 15) { // 16 bytes per line
                System.out.println("");
                j = -1; // reset j to 0
            }
        }
    }
    /**
     * Writes bytes to file in hexadecimal format and displays it on the console as well as in the file
     * @param bytes bytes to write
     * @param fileToWrite file to write to
     */
    public static void writeToFile(byte[] bytes, String fileToWrite) {
        try { // write to file
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(fileToWrite));
            bufferedOutputStream.write(bytes, 0, bytes.length);
            bufferedOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.out.println("Message digest has been successfully written to file: " + fileToWrite);
        }
    }
    /**
     * Reads the file specified in parameter and returns the byte array
     * @param fileToRead the file to read from
     */
    public static byte[] readToFile(String fileToRead) {
        try { // read from file
            BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToRead));
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
            return buffer;
        } catch(Exception e) {
            e.printStackTrace();
            return new byte[0];
            //return null;
        }
    }
    /**
     * Reads the Public Key from the file specified in keyFileName
     * @param keyFileName the key file to read from
     * @return the public key
     */
    public static PublicKey readPubKeyFromFile (String keyFileName) {
        try (FileInputStream fileInputStream = new FileInputStream(keyFileName); ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(fileInputStream))) { // read public key from file
            BigInteger m = (BigInteger) objectInputStream.readObject();
            BigInteger e = (BigInteger) objectInputStream.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error!", e);
        }
    }
    /**
     * Reads the Symmetric Key from the file specified in keyFileName
     * @param keyFileName the key file to read from
     * @return the symmetric key
     */
    public static String readSymmetricKeyFromFile(String keyFileName) {
        try { // read symmetric key from file
            FileReader fileReader = new FileReader(keyFileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            return bufferedReader.readLine();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
