package crypto;

import crypto.enums.Curve;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.*;
import java.util.Arrays;

public class ECCrypto {

    public static KeyPair generateKeyPair(Curve curve) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "SunEC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curve.name);
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] getRawData(PrivateKey privateKey) {
        byte[] result = ((ECPrivateKey) privateKey).getS().toByteArray();
        if (result.length > 32) {
            result = Arrays.copyOfRange(result, result.length-32, result.length);
        }
        return result;
    }

    public static byte[] getRawData(PublicKey publicKey) {
        byte[] result = publicKey.getEncoded();
        if (result.length > 65) {
            result = Arrays.copyOfRange(result, result.length-65, result.length);
        }
        return result;
    }

    public static PrivateKey getPrivateKey(Curve curve, byte[] bytes) throws Exception {
        AlgorithmParameters algoParams = AlgorithmParameters.getInstance("EC");
        algoParams.init(new ECGenParameterSpec(curve.name));
        ECParameterSpec ecSpec = algoParams.getParameterSpec(ECParameterSpec.class);

        BigInteger s = new BigInteger(1, bytes);

        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, ecSpec);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey getPublicKey(Curve curve, byte[] bytes) throws Exception {
        AlgorithmParameters algoParams = AlgorithmParameters.getInstance("EC");
        algoParams.init(new ECGenParameterSpec(curve.name));
        ECParameterSpec ecSpec = algoParams.getParameterSpec(ECParameterSpec.class);

        ECPoint point;
        if (bytes[0] == 0x04) {
            // UNCOMPRESSED
            int keySizeBytes = (bytes.length-1)/2;
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(bytes, 1, 1 + keySizeBytes));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(bytes, 1 + keySizeBytes, bytes.length));
            point = new ECPoint(x, y);
        } else if (bytes[0] == 0x02 || bytes[0] == 0x03){
            // COMPRESSED
            byte yByte = bytes[0];
            byte[] xBytes = Arrays.copyOfRange(bytes, 1, bytes.length);
            BigInteger x = new BigInteger(1, xBytes);
            BigInteger y = calculateY(ecSpec, x, yByte);
            point = new ECPoint(x, y);
        } else {
            throw new IllegalArgumentException("Invalid public key format ");
        }

        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    // y^2 = x^3 + ax + b
    private static BigInteger calculateY(ECParameterSpec ecSpec, BigInteger x, byte yByte) {
        EllipticCurve ecCurve = ecSpec.getCurve();
        BigInteger p = ((ECFieldFp) ecCurve.getField()).getP();
        BigInteger a = ecCurve.getA();
        BigInteger b = ecCurve.getB();
        BigInteger x3 = x.pow(3);
        BigInteger ax = a.multiply(x);
        BigInteger ySquare = x3.add(ax).add(b).mod(p);
        BigInteger y = ySquare.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
        if (y.testBit(0) != (yByte == 0x03)) {
            y = p.subtract(y);
        }
        return y;
    }

    public static byte[] generateECDHSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

}
