package org.suai.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.suai.crypto.analysis.LinearCryptAnalyzer;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.LinearApproximation;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork();
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
