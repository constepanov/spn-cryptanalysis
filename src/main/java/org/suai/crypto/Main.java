package org.suai.crypto;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.math3.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.suai.crypto.analysis.DifferentialCryptAnalyzer;
import org.suai.crypto.analysis.LinearCryptAnalyzer;
import org.suai.crypto.spn.SBoxProvider;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.LinearApproximation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        diffCryptanalysis();
    }

    private static void diffCryptanalysis() {
        BidiMap<String, String> sBox = SBoxProvider.getForDiffAnalysis();
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork(sBox);
        DifferentialCryptAnalyzer analyzer = new DifferentialCryptAnalyzer(spn);
        int[][] table = analyzer.getDifferenceDistributionTable();
        logger.info("Difference distribution table");
        for (int[] row : table) {
            logger.info(Arrays.toString(row));
        }
        String key = "110101001";
        String inputDifference = "110000000";
        Map<Pair<String, String>, Pair<String, String>> pairs = analyzer.generateCiphertextAndPlaintext(
                5, key, inputDifference);
        pairs.entrySet().forEach(System.out::println);
    }

    private static void linearCryptanalysis() {
        BidiMap<String, String> sBox = SBoxProvider.getForLinearAnalysis();
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork(sBox);
        LinearCryptAnalyzer analyzer = new LinearCryptAnalyzer(spn);
        int[][] table = analyzer.buildApproximationTable();
        logger.info("Linear approximation table");
        for (int[] row : table) {
            logger.info(Arrays.toString(row));
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

        String key = "110101001";
        logger.info("Key: " + key);
        int numberOfPairs = 100;
        Map<String, String> pairs = analyzer.generateCiphertextAndPlaintext(numberOfPairs, key);
        logger.info("Plain and ciphertext sample pairs");
        pairs.entrySet().stream().limit(5).forEach(entry ->
                logger.info("{} --- {}", entry.getKey(), entry.getValue()));
        List<LinearApproximation> keyEquations = analyzer.getKeyEquations(approximations, pairs);
        logger.info("Key equations");
        keyEquations.forEach(equation -> logger.info(equation.toString()));
    }
}
