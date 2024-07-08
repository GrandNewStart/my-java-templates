package encoding;

import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class Base64Utils {

    public static byte[] encodeToBytes(String text) {
        return Base64.getUrlEncoder().withoutPadding().encode(text.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] encodeToBytes(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encode(bytes);
    }

    public static String encodeToString(String text) {
        byte[] encoded = Base64.getUrlEncoder().withoutPadding().encode(text.getBytes(StandardCharsets.UTF_8));
        return new String(encoded, StandardCharsets.UTF_8);
    }

    public static String encodeToString(byte[] bytes) {
        byte[] encoded = Base64.getUrlEncoder().withoutPadding().encode(bytes);
        return new String(encoded, StandardCharsets.UTF_8);
    }

    public static byte[] decodeToBytes(byte[] bytes) {
        return Base64.getUrlDecoder().decode(bytes);
    }

    public static byte[] decodeToBytes(String text) {
        return Base64.getUrlDecoder().decode(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String decodeToString(byte[] bytes) {
        byte[] decoded = Base64.getUrlDecoder().decode(bytes);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    public static String decodeToString(String text) {
        byte[] decoded = Base64.getUrlDecoder().decode(text.getBytes(StandardCharsets.UTF_8));
        return new String(decoded, StandardCharsets.UTF_8);
    }

}
