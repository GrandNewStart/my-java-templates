import crypto.CryptoUtils;
import crypto.ECCrypto;
import crypto.enums.Curve;
import encoding.Base64Utils;
import encoding.HexUtils;
import json.JSONObject;

import javax.crypto.KeyAgreement;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Set;

public class Main {

    private static final String testString = "Hello, World!";
    private static final byte[] testBytes = testString.getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
//        testBase64();
//        testHexString();
//        testJSONObject();
        testECC();
    }

    public static void testBase64() {
        System.out.println("testBase64");
        String base64_1 = Base64Utils.encodeToString(testString);
        String base64_2 = Base64Utils.encodeToString(testBytes);
        byte[] base64_3 = Base64Utils.encodeToBytes(testString);
        byte[] base64_4 = Base64Utils.encodeToBytes(testBytes);
        System.out.println("testBase64: " + base64_1);
        System.out.println("testBase64: " + base64_2);
        System.out.println("testBase64: " + new String(base64_3, StandardCharsets.UTF_8));
        System.out.println("testBase64: " + new String(base64_4, StandardCharsets.UTF_8));
        System.out.print("\n");
    }

    public static void testHexString() {
        System.out.println("testHexString");
        String hex_1 = HexUtils.plainToHex(testString);
        String hex_2 = HexUtils.bytesToHex(testBytes);
        byte[] plain_1 = HexUtils.hexToBytes(hex_1);
        byte[] plain_2 = HexUtils.hexToBytes(hex_2);
        System.out.println("testHexString: " + hex_1);
        System.out.println("testHexString: " + hex_2);
        System.out.println("testHexString: " + new String(plain_1, StandardCharsets.UTF_8));
        System.out.println("testHexString: " + new String(plain_2, StandardCharsets.UTF_8));
        System.out.print("\n");
    }

    public static void testJSONObject() {
        System.out.println("testJSONObject");
        JSONObject json1 = new JSONObject();
        json1.addString("k1", "String");
        json1.addInteger("k2", 1);
        json1.addDouble("k3", 0.45);
        json1.addBoolean("k4", true);

        JSONObject json2 = new JSONObject();
        json2.addString("k5-1", "String");
        json2.addInteger("k5-2", 1);
        json2.addDouble("k5-3", 0.45);
        json2.addBoolean("k5-4", true);

        JSONObject json3 = new JSONObject();
        json3.addString("k5-5-1", "String");
        json3.addInteger("k5-5-2", 1);
        json3.addDouble("k5-5-3", 0.45);
        json3.addBoolean("k5-5-4", true);

        json2.addJSONObject("k5-5", json3);
        json1.addJSONObject("k5", json2);

        System.out.println("json1: " + json1);
        System.out.println("json2: " + json2);
        System.out.println("json3: " + json3);

        JSONObject json4 = new JSONObject(json1.toString());
        JSONObject json5 = new JSONObject(json2.toString());
        JSONObject json6 = new JSONObject(json3.toString());
        System.out.println("json4: " + json4);
        System.out.println("json5: " + json5);
        System.out.println("json6: " + json6);
        System.out.print("\n");
    }

    public static void testECC() {
        try {
            KeyPair kp1 = ECCrypto.generateKeyPair(Curve.P256);
            KeyPair kp2 = ECCrypto.generateKeyPair(Curve.P256);

            byte[] prv1 = ECCrypto.getRawData(kp1.getPrivate());
            byte[] pub1 = ECCrypto.getRawData(kp1.getPublic());
            byte[] prv2 = ECCrypto.getRawData(kp2.getPrivate());
            byte[] pub2 = ECCrypto.getRawData(kp2.getPublic());

            System.out.println("PRV1: (" + prv1.length + " bytes) " + HexUtils.bytesToHex(prv1));
            System.out.println("PUB1: (" + pub1.length + " bytes) " + HexUtils.bytesToHex(pub1));
            System.out.println("PRV2: (" + prv2.length + " bytes) " + HexUtils.bytesToHex(prv2));
            System.out.println("PUB2: (" + pub2.length + " bytes) " + HexUtils.bytesToHex(pub2));

            PrivateKey prv11 = ECCrypto.getPrivateKey(Curve.P256, prv1);
            System.out.println(HexUtils.bytesToHex(prv11.getEncoded()));

            PrivateKey prv22 = ECCrypto.getPrivateKey(Curve.P256, prv2);
            System.out.println(HexUtils.bytesToHex(prv22.getEncoded()));

            PublicKey pub11 = ECCrypto.getPublicKey(Curve.P256, pub1);
            System.out.println(HexUtils.bytesToHex(pub11.getEncoded()));
            System.out.println(HexUtils.bytesToHex(kp1.getPublic().getEncoded()));

            PublicKey pub22 = ECCrypto.getPublicKey(Curve.P256, pub2);
            System.out.println(HexUtils.bytesToHex(pub22.getEncoded()));
            System.out.println(HexUtils.bytesToHex(kp2.getPublic().getEncoded()));

            byte[] sec1 = ECCrypto.generateECDHSharedSecret(prv11, pub22);
            byte[] sec2 = ECCrypto.generateECDHSharedSecret(prv22, pub11);
            System.out.println(HexUtils.bytesToHex(sec1));
            System.out.println(HexUtils.bytesToHex(sec2));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}