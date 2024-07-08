package crypto.enums;

public enum KeySize {
    RSA_512(512),
    RSA_1024(1024),
    RSA_2048(2048),
    RSA_3072(3072),
    RSA_4096(4096),
    RSA_8192(8192);

    public final int bits;

    KeySize(int bits) {
        this.bits = bits;
    }
}
