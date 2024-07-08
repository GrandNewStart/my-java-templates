package crypto;

import crypto.enums.AESAlgorithm;
import crypto.enums.Curve;
import crypto.enums.KeySize;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CryptoUtils {

    public static byte[] sha256(byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(bytes);
    }

    public static byte[] generateRandomBytes(int size) {
        return new SecureRandom().generateSeed(size);
    }

    /**
     * Generates an RSA key pair with the specified key size.
     *
     * @param keySize the size of the keys to generate, in bits
     * @return a KeyPair containing the RSA public and private keys
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     */
    public static KeyPair generateRSAKeyPair(KeySize keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize.bits, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    // Method to encrypt data using RSA public key
    public static byte[] encryptRSA(byte[] data, byte[] publicKeyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Method to decrypt data using RSA private key
    public static byte[] decryptRSA(byte[] data, byte[] privateKeyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // Method to sign data using RSA private key
    public static byte[] createRSASignature(byte[] data, byte[] privateKeyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    // Method to verify RSA signature using RSA public key
    public static boolean verifyRSASignature(byte[] data, byte[] signatureBytes, byte[] publicKeyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(spec);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    /**
     * Generates an EC key pair with the specified curve name.
     * Replace the "SunEC" with the provider that you wish to use, such as BouncyCastle.
     *
     * @param curve the type of the elliptic curve to use (e.g., "secp256r1", "prime256v1")
     * @return a KeyPair containing the EC public and private keys
     * @throws NoSuchAlgorithmException if the EC algorithm is not available
     * @throws NoSuchProviderException if the specified provider is not available
     * @throws InvalidAlgorithmParameterException if the specified curve is invalid
     */
    public static KeyPair generateECKeyPair(Curve curve)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "SunEC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve.name);
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    // Method to create ECDH shared secret
    public static byte[] createECDHSharedSecret(byte[] privateKeyBytes, byte[] publicKeyBytes)
            throws Exception {
        // Convert the private key bytes into a PrivateKey object
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Convert the public key bytes into a PublicKey object
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Initialize the KeyAgreement with the private key
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);

        // Perform phase with the public key
        keyAgreement.doPhase(publicKey, true);

        // Generate the shared secret
        return keyAgreement.generateSecret();
    }

    // Method to encrypt data using AES algorithm
    public static byte[] encryptAES(AESAlgorithm algorithm, byte[] data, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(algorithm.name);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(data);
    }

    // Method to decrypt data using AES algorithm
    public static byte[] decryptAES(AESAlgorithm algorithm, byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(algorithm.name);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(encryptedData);
    }

    // Method to create ECDSA signature
    public static byte[] createECDSASignature(byte[] data, byte[] privateKeyBytes) throws Exception {
        // Convert the private key bytes into a PrivateKey object
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Initialize the Signature object for signing
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);

        // Generate the signature
        return signature.sign();
    }

    // Method to verify ECDSA signature
    public static boolean verifyECDSASignature(byte[] data, byte[] signatureBytes, byte[] publicKeyBytes) throws Exception {
        // Convert the public key bytes into a PublicKey object
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Initialize the Signature object for verification
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(data);

        // Verify the signature
        return signature.verify(signatureBytes);
    }

}
