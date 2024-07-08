package crypto.enums;

public enum AESAlgorithm {
    AES_128_CBC("AES/CBC/PKCS5Padding"),
    AES_192_CBC("AES/CBC/PKCS5Padding"),
    AES_256_CBC("AES/CBC/PKCS5Padding"),

    AES_128_GCM("AES/GCM/PKCS5Padding"),
    AES_192_GCM("AES/GCM/PKCS5Padding"),
    AES_256_GCM("AES/GCM/PKCS5Padding");

    public final String name;

    AESAlgorithm(String name) {
        this.name = name;
    }
}
