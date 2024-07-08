import encoding.Base64Utils;
import encoding.HexUtils;
import json.JSONObject;

import java.nio.charset.StandardCharsets;

public class Main {

    private static final String testString = "Hello, World!";
    private static final byte[] testBytes = testString.getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        testBase64();
        testHexString();
        testJSONObject();
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

}