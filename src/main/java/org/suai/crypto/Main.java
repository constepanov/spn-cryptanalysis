package org.suai.crypto;

import org.apache.commons.collections4.BidiMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.suai.crypto.analysis.DifferentialCryptAnalyzer;
import org.suai.crypto.analysis.LinearCryptAnalyzer;
import org.suai.crypto.spn.SBoxProvider;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.LinearApproximation;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws IOException {
        logger.debug("Linear cryptanalysis");
        linearCryptanalysis();
        logger.debug("Differential cryptanalysis");
        differentialCryptanalysis();
    }

    private static void differentialCryptanalysis() throws IOException {
        int taskNumber = 7;
        String pathname = String.format("src/main/resources/diff/sbox-%d.txt", taskNumber);
        File file = new File(pathname);
        BidiMap<String, String> sBox = SBoxProvider.readFromFile(file, 3);
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork(sBox);
        DifferentialCryptAnalyzer analyzer = new DifferentialCryptAnalyzer(spn);
        int[][] table = analyzer.getDifferenceDistributionTable();
        logger.info("Difference distribution table");
        for (int[] row : table) {
            logger.info(Arrays.toString(row));
        }
        String key = "101011001";
        // Konstantin 7
        List<String> inputDifference = Arrays.asList("000110000", "000000110", "000101000", "000000101");

        // Vika 1
        //List<String> inputDifference = Arrays.asList("100000000", "000011000", "000000011");

        // Alexey 2
        //List<String> inputDifference = Arrays.asList("100000000", "000100000", "000011000");

        // Ivan 3
        //List<String> inputDifference = Arrays.asList("000101000", "000011000");

        int num = 5;
        Map<Integer, Set<String>> subKeys = analyzer.analyzeInputDifferences(inputDifference, num, key);
        System.out.println(subKeys);
    }

    private static void linearCryptanalysis() throws IOException {
        int taskNumber = 2;
        String pathname = String.format("src/main/resources/linear/sbox-%d.txt", taskNumber);
        File file = new File(pathname);
        BidiMap<String, String> sBox = SBoxProvider.readFromFile(file, 3);
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork(sBox);
        LinearCryptAnalyzer analyzer = new LinearCryptAnalyzer(spn);
        int[][] table = analyzer.buildApproximationTable();
        logger.info("Linear approximation table");
        for (int[] row : table) {
            logger.info(Arrays.toString(row));
        }

        List<String> inputs = analyzer.getInputs();
        logger.info("Inputs: " + inputs);

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
