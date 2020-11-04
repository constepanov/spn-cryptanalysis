package org.suai.crypto.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class LinearApproximation {
    private List<EquationElement> leftPart;
    private List<EquationElement> rightPart;
    private double probability;

    public LinearApproximation() {

    }

    public LinearApproximation(List<EquationElement> leftPart, List<EquationElement> rightPart) {
        this.leftPart = leftPart;
        this.rightPart = rightPart;
    }

    public LinearApproximation(List<EquationElement> leftPart, List<EquationElement> rightPart, double probability) {
        this.leftPart = leftPart;
        this.rightPart = rightPart;
        this.probability = probability;
    }

    public LinearApproximation moveToLeft(EquationElement element) {
        List<EquationElement> left = Collections.singletonList(element);
        List<EquationElement> right = new ArrayList<>(leftPart);
        right.addAll(rightPart);
        right.remove(element);
        return new LinearApproximation(left, right, probability);
    }

    public LinearApproximation replaceInLeft(LinearApproximation replacementEquation) {
        List<EquationElement> resultLeftPart = new ArrayList<>(leftPart);
        List<EquationElement> resultRightPart = new ArrayList<>(rightPart);
        resultLeftPart.remove(replacementEquation.getLeftPart().get(0));
        resultLeftPart.addAll(replacementEquation.getRightPart());
        return new LinearApproximation(resultLeftPart, resultRightPart, probability);
    }

    @Override
    public String toString() {
        return partToString(leftPart) + " = " +
                partToString(rightPart) +
                " p = " + probability;
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

    public void setLeftPart(List<EquationElement> leftPart) {
        this.leftPart = leftPart;
    }

    public void setRightPart(List<EquationElement> rightPart) {
        this.rightPart = rightPart;
    }

    public void setProbability(double probability) {
        this.probability = probability;
    }

    public List<EquationElement> getLeftPart() {
        return leftPart;
    }

    public List<EquationElement> getRightPart() {
        return rightPart;
    }

    public double getProbability() {
        return probability;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LinearApproximation that = (LinearApproximation) o;
        return Double.compare(that.probability, probability) == 0 &&
                leftPart.equals(that.leftPart) &&
                rightPart.equals(that.rightPart);
    }

    @Override
    public int hashCode() {
        return Objects.hash(leftPart, rightPart, probability);
    }
}
