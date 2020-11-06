package org.suai.crypto;

import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.BinaryString;
import org.suai.crypto.util.LinearApproximation;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.suai.crypto.analysis.LinearCryptAnalyzer.*;

public class Main {
    public static void main(String[] args) {
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork();
        int[][] table = buildApproximationTable(spn.getSBox());
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

        List<LinearApproximation> approximations = getSPNApproximations(table, inputs);

        String key = "110001110";
        System.out.println("Key: " + key);
        int numberOfPairs = 100;
        Map<String, String> pairs = generateCiphertextAndPlaintext(numberOfPairs, key);
        List<LinearApproximation> keyEquations = getKeyEquations(approximations, pairs);
        System.out.println("Key equations:");
        keyEquations.forEach(System.out::println);
    }
}
