package org.suai.crypto;

import org.suai.crypto.analysis.LinearCryptAnalyzer;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.EquationElement;
import org.suai.crypto.util.EquationElementType;
import org.suai.crypto.util.LinearApproximation;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork();
        int[][] table = LinearCryptAnalyzer.buildApproximationTable(spn.getSBox());
        for (int[] row : table) {
            System.out.println(Arrays.toString(row));
        }
        EquationElement elem = new EquationElement(7, 1, EquationElementType.KEY);
        EquationElement elem2 = new EquationElement(8, 1, EquationElementType.KEY);
        EquationElement elem3 = new EquationElement(9, 1, EquationElementType.KEY);
        LinearApproximation appr = new LinearApproximation();
        appr.setLeftPart(Arrays.asList(elem, elem2, elem3));
        appr.setRightPart(Arrays.asList(elem2,elem3));
        System.out.println(appr);
    }
}
