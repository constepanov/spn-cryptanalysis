package org.suai.crypto.util;

public enum EquationElementType {
    PLAINTEXT("X"),
    CIPHERTEXT("Y"),
    KEY("K"),
    S_BOX_INPUT("U"),
    S_BOX_OUTPUT("V");

    private String name;

    EquationElementType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
