package org.suai.crypto.util;

import java.util.List;

public class LinearApproximation {
    private List<EquationElement> leftPart;
    private List<EquationElement> rightPart;
    private double probability;

    public void setLeftPart(List<EquationElement> leftPart) {
        this.leftPart = leftPart;
    }

    public void setRightPart(List<EquationElement> rightPart) {
        this.rightPart = rightPart;
    }

    public void setProbability(double probability) {
        this.probability = probability;
    }

    @Override
    public String toString() {
        return partToString(leftPart) + " = " + partToString(rightPart);
    }

    private String partToString(List<EquationElement> part) {
        if (part.isEmpty()) {
            return "0";
        }
        StringBuilder equationPart = new StringBuilder();
        for (int i = 0; i < part.size(); i++) {
            equationPart.append(part.get(i));
            if (i != part.size() - 1) {
                equationPart.append(" + ");
            }
        }
        return equationPart.toString();
    }
}
