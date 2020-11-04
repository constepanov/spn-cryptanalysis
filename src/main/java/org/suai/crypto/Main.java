package org.suai.crypto;

import org.suai.crypto.analysis.LinearCryptAnalyzer;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.EquationElement;
import org.suai.crypto.util.EquationElementType;
import org.suai.crypto.util.LinearApproximation;

import java.util.Arrays;
import java.util.stream.IntStream;

public class Main {
    public static void main(String[] args) {
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork();
        int[][] table = LinearCryptAnalyzer.buildApproximationTable(spn.getSBox());
        for (int[] row : table) {
            System.out.println(Arrays.toString(row));
        }
        String input = "000010000";
        LinearCryptAnalyzer.buildSPNApproximation(table, input);
    }
}
