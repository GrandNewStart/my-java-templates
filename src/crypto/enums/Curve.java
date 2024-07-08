package crypto.enums;

public enum Curve {
    SECP256K1("secp256k1"),
    SECP256R1("secp256r1"),
    PRIME256V1("prime256v1");

    public final String name;

    Curve(String name) {
        this.name = name;
    }
}
