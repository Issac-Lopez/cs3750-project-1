//Name
//CS3750
//PROJECT 1
package project1.KeyGen;

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
        Scanner input = new Scanner(System.in);
        String symmetric = "";
        boolean loop = true;
        while (loop) {
            System.out.print("Enter what you want the symmetric key to be (16 characters long) : ");
            symmetric = input.nextLine();
            if (symmetric.length() == 16) {
                loop = false;
            } else {
                System.out.println("The symmetric key that you entered has a character length of " + symmetric.length());
                System.out.println("The symmetric key's length needs to be 16 characters long\n");
            }
        }
        input.close();
        // PrintWriter out = new PrintWriter("symmetric.key");
        BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream("symmetric.key"));
        byte[] key = symmetric.getBytes(StandardCharsets.UTF_8);
        output.write(key, 0, key.length);
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);
        KeyPair pair = generator.generateKeyPair();
        Key pubKeyX = pair.getPublic();
        Key privKeyX = pair.getPrivate();
        KeyPairGenerator generator2 = KeyPairGenerator.getInstance("RSA");
        generator2.initialize(1024, random);
        KeyPair pair2 = generator2.generateKeyPair();
        Key pubKeyY = pair2.getPublic();
        Key privKeyY = pair2.getPrivate();
        output.close();
    /* next, store the keys to files, read them back from files,
       and then, encrypt & decrypt using the keys from files. */
        // Get the components of the public/private keys and store them to files
        // get the parameters of the keys: modulus and exponent
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpecX = factory.getKeySpec(pubKeyX, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpecX = factory.getKeySpec(privKeyX, RSAPrivateKeySpec.class);
        RSAPublicKeySpec pubKSpecY = factory.getKeySpec(pubKeyY, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpecY = factory.getKeySpec(privKeyY, RSAPrivateKeySpec.class);

        saveToFile("XPublic.key", pubKSpecX.getModulus(), pubKSpecX.getPublicExponent());
        saveToFile("XPrivate.key", privKSpecX.getModulus(), privKSpecX.getPrivateExponent());
        saveToFile("YPublic.key", pubKSpecY.getModulus(), pubKSpecY.getPublicExponent());
        saveToFile("YPrivate.key", privKSpecY.getModulus(), privKSpecY.getPrivateExponent());
    }
    //save the parameters of the public and private keys to file
    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        System.out.println("Write to " + fileName + ": modulus = " + mod.toString() + "; exponent = " + exp.toString() + "\n");
        // create a file to store the keys
        ObjectOutputStream out = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        try { // write the modulus and the exponent to the file
            out.writeObject(mod);
            out.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            out.close();
        }
    }
}
