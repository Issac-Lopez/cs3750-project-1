import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.math.BigInteger;
import java.util.Scanner;

public class KeyGen {
    public static void main(String[] args) throws Exception {
        Scanner scn = new Scanner(System.in);
        String symmetric="";
        boolean loop = true;

        while (loop) { // loop until user enters a 16 character string
            System.out.println("======================================================================");
            System.out.println("======== Enter 16 character long string for the symmetric key ========");
            System.out.println("======================================================================");
            symmetric = scn.nextLine();
            if (symmetric.length() == 16) { // if the string is 16 characters long, exit the loop
                loop = false;
            } else { // if the string is not 16 characters long, print an error message and loop again
                System.out.println("The symmetric key that you entered has a character length of " + symmetric.length());
                System.out.println("The symmetric key's length needs to be 16 characters long!\n");
            }
        }
        scn.close();
        BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream("symmetric.key"));
        byte[] key = symmetric.getBytes(StandardCharsets.UTF_8); // convert the string to a byte array
        output.write(key, 0, key.length);

        // Generate a pair of keys
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); // generate a key pair for X
        generator.initialize(1024, random);  //1024: key size in bits

        KeyPair pair = generator.generateKeyPair(); // generate the key pair
        Key pubKeyX = pair.getPublic();
        Key privKeyX = pair.getPrivate();

        KeyPairGenerator generator2 = KeyPairGenerator.getInstance("RSA"); // generate a key pair for Y
        generator2.initialize(1024, random);
        KeyPair pair2 = generator2.generateKeyPair();
        Key pubKeyY = pair2.getPublic();
        Key privKeyY = pair2.getPrivate();
        output.close();

        // get modulus and exponent of the keys
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpecX = factory.getKeySpec(pubKeyX, RSAPublicKeySpec.class); // get the public key parameters for X
        RSAPrivateKeySpec privKSpecX = factory.getKeySpec(privKeyX,RSAPrivateKeySpec.class); // get the private key parameters for X

        RSAPublicKeySpec pubKSpecY = factory.getKeySpec(pubKeyY, RSAPublicKeySpec.class); // get the public key parameters for Y
        RSAPrivateKeySpec privKSpecY = factory.getKeySpec(privKeyY, RSAPrivateKeySpec.class); // get the private key parameters for Y

        // save the keys to .key files
        saveToFile("XPublic.key", pubKSpecX.getModulus(), pubKSpecX.getPublicExponent());
        saveToFile("XPrivate.key", privKSpecX.getModulus(), privKSpecX.getPrivateExponent());

        saveToFile("YPublic.key", pubKSpecY.getModulus(), pubKSpecY.getPublicExponent());
        saveToFile("YPrivate.key", privKSpecY.getModulus(), privKSpecY.getPrivateExponent());
    }

    /**
     * Save the key to a file
     * @param fileName the name of the file
     * @param mod the modulus
     * @param exp the exponent
     * @throws IOException if an I/O error occurs
     */
    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {

        System.out.println("Write to " + fileName + ":\nmodulus = " + mod.toString() + ",\nexponent = " + exp.toString() + "\n");

        try (ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)))) { // write the key to a file
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        }
    }
}