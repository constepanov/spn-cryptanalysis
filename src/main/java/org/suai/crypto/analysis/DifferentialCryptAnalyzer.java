package org.suai.crypto.analysis;

import com.google.common.base.Splitter;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.math3.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.BinaryString;

import java.util.*;
import java.util.function.IntPredicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class DifferentialCryptAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(DifferentialCryptAnalyzer.class);

    private final SubstitutionPermutationNetwork spn;
    private final int[][] table;

    public DifferentialCryptAnalyzer(SubstitutionPermutationNetwork spn) {
        this.spn = spn;
        this.table = buildDifferenceDistributionTable();
    }

    private int[][] buildDifferenceDistributionTable() {
        BidiMap<String, String> sBox = spn.getSBox();
        int sBoxInputSize = spn.getSBoxInputSize();
        int size = (int) Math.pow(2, sBoxInputSize);
        int[][] table = new int[size][size];
        for (int row = 0; row < size; row++) {
            String inputDifference = BinaryString.valueOf(row, sBoxInputSize);
            Map<String, String> combinations = getCombinationsForDifference(inputDifference);
            for (Map.Entry<String, String> entry : combinations.entrySet()) {
                String firstOutput = sBox.get(entry.getKey());
                String secondOutput = sBox.get(entry.getValue());
                String outputDifference = BinaryString.xor(firstOutput, secondOutput);
                int column = Integer.parseInt(outputDifference, 2);
                table[row][column]++;
            }
        }
        return table;
    }

    private Map<String, String> getCombinationsForDifference(String inputDifference) {
        Map<String, String> combinations = new HashMap<>();
        int length = inputDifference.length();
        int numberOfCombinations = (int) Math.pow(2, length);
        for (int i = 0; i < numberOfCombinations; i++) {
            String first = BinaryString.valueOf(i, length);
            String second = BinaryString.xor(first, inputDifference);
            combinations.put(first, second);
        }
        return combinations;
    }

    public List<String> getInputDifferences(String outputDifference) {
        int column = Integer.parseInt(outputDifference, 2);
        return getDifferences(i -> table[i][column] != 0);
    }

    public List<String> getOutputDifferences(String inputDifference) {
        int row = Integer.parseInt(inputDifference, 2);
        return getDifferences(i -> table[row][i] != 0);
    }

    private List<String> getDifferences(IntPredicate predicate) {
        return IntStream.range(0, table.length)
                .filter(predicate)
                .mapToObj(i -> BinaryString.valueOf(i, 3))
                .collect(Collectors.toList());
    }

    public String getLastRoundInputDifferences(String inputDifferenceBlock) {
        int[] bitPermutation = spn.getBitPermutation();

        logger.debug("First round input difference: {}", inputDifferenceBlock);
        String sBoxOutputDifference = getSBoxOutputDifference(inputDifferenceBlock);
        logger.debug("First round output difference: {}", sBoxOutputDifference);
        String sBoxInputDifference = BinaryString.permute(sBoxOutputDifference, bitPermutation);

        logger.debug("Second round input difference: {}", sBoxOutputDifference);
        sBoxOutputDifference = getSBoxOutputDifference(sBoxInputDifference);
        logger.debug("Second round output difference: {}", sBoxOutputDifference);

        sBoxInputDifference = BinaryString.permute(sBoxOutputDifference, bitPermutation);
        logger.debug("Third round input difference: {}", sBoxInputDifference);

        return sBoxInputDifference;
    }

    public Map<Pair<String, String>, Pair<String, String>> generateCiphertextAndPlaintext(
            int num,
            String key,
            String inputDifferenceBlock) {
        int blockSize = spn.getBlockSize();
        Map<Pair<String, String>, Pair<String, String>> pairs = new HashMap<>();
        while (pairs.size() <= num) {
            String firstPlaintext = BinaryString.random(blockSize);
            String secondPlaintext = BinaryString.xor(firstPlaintext, inputDifferenceBlock);
            String firstCiphertext = spn.encrypt(firstPlaintext, key);
            String secondCiphertext = spn.encrypt(secondPlaintext, key);
            pairs.put(new Pair<>(firstPlaintext, firstCiphertext),
                    new Pair<>(secondPlaintext, secondCiphertext));
        }
        return pairs;
    }

    private Map<Integer, List<String>> getPossibleSubKeys(String outputDifferenceBlock,
                                                          List<String> lastRoundDifferences) {
        return null;
    }

    private String getSBoxOutputDifference(String inputDifferenceBlock) {
        StringBuilder result = new StringBuilder();
        for (String input : Splitter.fixedLength(spn.getSBoxInputSize()).split(inputDifferenceBlock)) {
            List<String> outputDiff = input.indexOf('x') == -1 ?
                    getOutputDifferences(input) : getUniqueOutputDifferences(input);
            char[] output = outputDiff.get(0).toCharArray();
            IntStream
                    .range(1, outputDiff.size())
                    .mapToObj(i -> BinaryString.xor(outputDiff.get(i - 1), outputDiff.get(i)))
                    .map(delta -> indicesOf(delta, '1'))
                    .forEach(indices -> indices.forEach(index -> output[index] = 'x'));
            result.append(String.valueOf(output));
        }
        return result.toString();
    }

    private List<String> getUniqueOutputDifferences(String partlyKnownInput) {
        Set<String> result = new HashSet<>();
        List<Integer> indices = indicesOf(partlyKnownInput, 'x');
        int length = indices.size();
        int iterations = (int) Math.pow(2, indices.size());
        char[] input = partlyKnownInput.toCharArray();
        for (int i = 0; i < iterations; i++) {
            String number = BinaryString.valueOf(i, length);
            IntStream.range(0, length)
                    .forEach(j -> input[indices.get(j)] = number.charAt(j));

            List<String> outputDiff = getOutputDifferences(String.valueOf(input));
            result.addAll(outputDiff);
        }
        return new ArrayList<>(result);
    }

    public int[][] getDifferenceDistributionTable() {
        return table;
    }

    private List<Integer> indicesOf(String value, char c) {
        List<Integer> indices = new ArrayList<>();
        int index = value.indexOf(c);
        while (index >= 0) {
            indices.add(index);
            index = value.indexOf(c, index + 1);
        }
        return indices;
    }
}
