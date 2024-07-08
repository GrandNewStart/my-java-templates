package encoding;

import java.nio.charset.StandardCharsets;

public class HexUtils {

    public static byte[] hexToBytes(String hexString) {
        if (hexString == null || hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string is invalid");
        }

        int length = hexString.length();
        byte[] bytes = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }

        return bytes;
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        StringBuilder hexString = new StringBuilder(2 * bytes.length);

        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }

        return hexString.toString();
    }

    public static String plainToHex(String plainText) {
        if (plainText == null) {
            return null;
        }

        byte[] bytes = plainText.getBytes(StandardCharsets.UTF_8);
        return bytesToHex(bytes);
    }

    public static String hexToPlain(String hexString) {
        if (hexString == null) {
            return null;
        }

        byte[] bytes = hexToBytes(hexString);
        return new String(bytes, StandardCharsets.UTF_8);
    }


}
