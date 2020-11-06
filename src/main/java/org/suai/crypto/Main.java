package org.suai.crypto;

import org.suai.crypto.analysis.LinearCryptAnalyzer;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.LinearApproximation;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Main {
    public static void main(String[] args) {
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork();
        LinearCryptAnalyzer analyzer = new LinearCryptAnalyzer(spn);
        int[][] table = analyzer.buildApproximationTable();
        for (int[] row : table) {
            System.out.println(Arrays.toString(row));
        }

        List<String> inputs = Arrays.asList(
                "000110000",
                "000010000",
                "000000110",
                "000000100",
                "100000100",
                "110000000",
                "111000000",
                "000111000"
        );

        List<LinearApproximation> approximations = analyzer.getSPNApproximations(table, inputs);

        String key = "110001110";
        System.out.println("Key: " + key);
        int numberOfPairs = 100;
        Map<String, String> pairs = analyzer.generateCiphertextAndPlaintext(numberOfPairs, key);
        List<LinearApproximation> keyEquations = analyzer.getKeyEquations(approximations, pairs);
        System.out.println("Key equations:");
        keyEquations.forEach(System.out::println);
    }
}
