package org.suai.crypto.util;

import org.apache.commons.math3.fraction.Fraction;

import java.util.*;

import static org.suai.crypto.util.EquationElementType.CIPHERTEXT;
import static org.suai.crypto.util.EquationElementType.PLAINTEXT;

public class LinearApproximation {
    private List<EquationElement> leftPart;
    private List<EquationElement> rightPart;
    private Fraction probability;

    public LinearApproximation() {
        this.leftPart = new ArrayList<>();
        this.rightPart = new ArrayList<>();
    }

    public LinearApproximation(List<EquationElement> leftPart, List<EquationElement> rightPart) {
        this(leftPart, rightPart, Fraction.ONE);
    }

    public LinearApproximation(List<EquationElement> leftPart,
                               List<EquationElement> rightPart,
                               Fraction probability) {
        this.leftPart = leftPart;
        this.rightPart = rightPart;
        this.probability = probability;
    }

    public void addToLeft(EquationElement element) {
        leftPart.add(element);
    }

    public void addToRight(EquationElement element) {
        rightPart.add(element);
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

    public void simplify() {
        moveAllToLeft();
        List<EquationElement> simplifiedLeftPart = new ArrayList<>();
        Map<EquationElement, Integer> elementCount = new HashMap<>();
        leftPart.forEach(element -> elementCount.put(element,
                elementCount.containsKey(element) ? elementCount.get(element) + 1 : 1));
        elementCount.forEach((key, value) -> {
            if (value % 2 == 1) {
                simplifiedLeftPart.add(key);
            }
        });
        leftPart = simplifiedLeftPart;
    }

    public void toStandardForm() {
        List<EquationElement> updatedLeftPart = new ArrayList<>();
        List<EquationElement> updatedRightPart = new ArrayList<>();
        for (EquationElement element : leftPart) {
            if (element.getType() == CIPHERTEXT || element.getType() == PLAINTEXT) {
                updatedLeftPart.add(element);
            } else {
                updatedRightPart.add(element);
            }
        }
        updatedLeftPart.sort(Comparator.comparing(EquationElement::getBitNumber));
        updatedRightPart.sort(Comparator.comparing(EquationElement::getBitNumber));
        leftPart = updatedLeftPart;
        rightPart = updatedRightPart;
    }

    private void moveAllToLeft() {
        leftPart.addAll(rightPart);
        rightPart.clear();
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

    public void setProbability(Fraction probability) {
        this.probability = probability;
    }

    public List<EquationElement> getLeftPart() {
        return leftPart;
    }

    public List<EquationElement> getRightPart() {
        return rightPart;
    }

    public Fraction getProbability() {
        return probability;
    }

    @Override
    public int hashCode() {
        return Objects.hash(leftPart, rightPart, probability);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LinearApproximation that = (LinearApproximation) o;
        return Objects.equals(leftPart, that.leftPart) &&
                Objects.equals(rightPart, that.rightPart) &&
                Objects.equals(probability, that.probability);
    }
}
