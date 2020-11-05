package org.suai.crypto;

import org.suai.crypto.analysis.LinearCryptAnalyzer;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork();
        int[][] table = LinearCryptAnalyzer.buildApproximationTable(spn.getSBox());
        for (int[] row : table) {
            System.out.println(Arrays.toString(row));
        }
        String input = "100100100";
        LinearCryptAnalyzer.buildSPNApproximation(table, input);
    }
}
