package org.suai.crypto.util;

import java.util.Objects;

public class EquationElement {
    private int bitNumber;
    private int roundNumber;
    private EquationElementType type;

    public EquationElement(int bitNumber, int roundNumber, EquationElementType type) {
        this.bitNumber = bitNumber;
        this.roundNumber = roundNumber;
        this.type = type;
    }

    @Override
    public String toString() {
        if (type == EquationElementType.S_BOX_INPUT || type == EquationElementType.S_BOX_OUTPUT) {
            return String.format("%s(%d, %d)", type.getName(), roundNumber, bitNumber);
        } else {
            return String.format("%s(%d)", type.getName(), bitNumber);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EquationElement that = (EquationElement) o;
        return bitNumber == that.bitNumber &&
                roundNumber == that.roundNumber &&
                type == that.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(bitNumber, roundNumber, type);
    }
}
