package org.suai.crypto.analysis;

import com.google.common.base.Splitter;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.math3.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;

import java.util.*;
import java.util.function.IntPredicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.suai.crypto.util.BinaryString.*;

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
            String inputDifference = valueOf(row, sBoxInputSize);
            Map<String, String> combinations = getCombinationsForDifference(inputDifference);
            for (Map.Entry<String, String> entry : combinations.entrySet()) {
                String firstOutput = sBox.get(entry.getKey());
                String secondOutput = sBox.get(entry.getValue());
                String outputDifference = xor(firstOutput, secondOutput);
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
            String first = valueOf(i, length);
            String second = xor(first, inputDifference);
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
                .mapToObj(i -> valueOf(i, 3))
                .collect(Collectors.toList());
    }

    public String getLastRoundInputDifferences(String inputDifferenceBlock) {
        int[] bitPermutation = spn.getBitPermutation();

        logger.debug("First round input difference: {}", inputDifferenceBlock);
        String sBoxOutputDifference = getSBoxOutputDifference(inputDifferenceBlock);
        logger.debug("First round output difference: {}", sBoxOutputDifference);
        String sBoxInputDifference = permute(sBoxOutputDifference, bitPermutation);

        logger.debug("Second round input difference: {}", sBoxInputDifference);
        sBoxOutputDifference = getSBoxOutputDifference(sBoxInputDifference);
        logger.debug("Second round output difference: {}", sBoxOutputDifference);

        sBoxInputDifference = permute(sBoxOutputDifference, bitPermutation);
        logger.debug("Third round input difference: {}", sBoxInputDifference);

        return sBoxInputDifference;
    }

    public List<Pair<Pair<String, String>, Pair<String, String>>> generateCiphertextAndPlaintext(
            int num,
            String key,
            String inputDifferenceBlock) {
        int blockSize = spn.getBlockSize();
        List<Pair<Pair<String, String>, Pair<String, String>>> pairs = new ArrayList<>();
        while (pairs.size() < num) {
            String firstPlaintext = random(blockSize);
            String secondPlaintext = xor(firstPlaintext, inputDifferenceBlock);
            String firstCiphertext = spn.encrypt(firstPlaintext, key);
            String secondCiphertext = spn.encrypt(secondPlaintext, key);
            pairs.add(new Pair<>(new Pair<>(firstPlaintext, secondPlaintext),
                    new Pair<>(firstCiphertext, secondCiphertext)));
        }
        return pairs;
    }

    public Map<Integer, Set<String>> analyzeInputDifferences(List<String> inputDifferences,
                                                             int numberOfPairs,
                                                             String key) {
        Map<Integer, Set<String>> subKeys = new HashMap<>();
        inputDifferences.forEach(inputDiff -> {
            String lastRoundInputDiff = getLastRoundInputDifferences(inputDiff);
            List<Pair<Pair<String, String>, Pair<String, String>>> pairs =
                    generateCiphertextAndPlaintext(numberOfPairs, key, inputDiff);
            pairs.forEach(p -> logger.debug("{}", p));
            pairs.forEach(p ->
                    updateSubKeys(subKeys, getSubKeys(lastRoundInputDiff, p.getSecond())));
        });
        return subKeys;
    }

    private Map<Integer, Set<String>> getSubKeys(String lastRoundInputDiff,
                                                 Pair<String, String> ciphertextPair) {
        Map<Integer, Set<String>> subKeys = new HashMap<>();
        logger.debug("Ciphertext pair {}", ciphertextPair);

        String ciphertextDiff = xor(ciphertextPair.getFirst(), ciphertextPair.getSecond());
        logger.debug("Ciphertext diff {}", ciphertextDiff);

        List<String> firstCTBlocks = split(ciphertextPair.getFirst(), spn.getSBoxInputSize());
        List<String> secondCTBlocks = split(ciphertextPair.getSecond(), spn.getSBoxInputSize());
        List<String> inputDiffBlocks = split(lastRoundInputDiff, spn.getSBoxInputSize());
        List<String> outputDiffBlocks = split(ciphertextDiff, spn.getSBoxInputSize());

        List<Integer> blockNumbers = getBlockNumbersForAnalysis(inputDiffBlocks, outputDiffBlocks);

        for (Integer blockNumber : blockNumbers) {
            logger.debug("Trying to find sub keys for block {}", blockNumber);
            String inputDiff = determineInputDifference(inputDiffBlocks.get(blockNumber),
                    outputDiffBlocks.get(blockNumber));
            Map<String, List<Pair<String, String>>> outputPairs = getOutputPairs(inputDiff);

            String outputDiff = outputDiffBlocks.get(blockNumber);
            Set<String> blockSubKeys = getSubKeyValues(outputPairs.get(outputDiff),
                    firstCTBlocks.get(blockNumber), secondCTBlocks.get(blockNumber));
            updateSubKeys(subKeys, blockSubKeys, blockNumber);
        }
        System.out.println(subKeys);
        return subKeys;
    }

    private void updateSubKeys(Map<Integer, Set<String>> subKeys,
                               Set<String> blockSubKeys, int blockNumber) {
        subKeys.putIfAbsent(blockNumber, blockSubKeys);
        subKeys.get(blockNumber).retainAll(blockSubKeys);
    }

    private void updateSubKeys(Map<Integer, Set<String>> subKeys,
                               Map<Integer, Set<String>> partialSubKeys) {
        partialSubKeys.forEach((blockNumber, keys) -> {
            subKeys.putIfAbsent(blockNumber, keys);
            subKeys.get(blockNumber).retainAll(keys);
        });
    }

    private String determineInputDifference(String inputDiff, String outputDiff) {
        List<String> inputDiffsForOutput = getInputDifferences(outputDiff);
        List<String> diffsForInput = replaceUnknownBits(inputDiff);
        inputDiffsForOutput.retainAll(diffsForInput);
        return inputDiffsForOutput.get(0);
    }

    public Set<String> getSubKeyValues(List<Pair<String, String>> outputPairs,
                                       String firstCiphertext,
                                       String secondCiphertext) {
        Set<String> values = new HashSet<>();
        for (Pair<String, String> outPair : outputPairs) {
            String subKey = xor(outPair.getFirst(), firstCiphertext);
            values.add(subKey);

            subKey = xor(outPair.getSecond(), secondCiphertext);
            values.add(subKey);
        }
        return values;
    }

    public Map<String, List<Pair<String, String>>> getOutputPairs(String inputDiff) {
        Map<String, String> combinations = getCombinationsForDifference(inputDiff);
        BidiMap<String, String> sBox = spn.getSBox();
        Map<String, List<Pair<String, String>>> outPairs = new HashMap<>();
        combinations.forEach((key, value) -> {
            String firstOutput = sBox.get(key);
            String secondOutput = sBox.get(value);
            String outputDiff = xor(firstOutput, secondOutput);
            Pair<String, String> outputPair = new Pair<>(firstOutput, secondOutput);
            outPairs.computeIfAbsent(outputDiff, k -> new ArrayList<>());
            outPairs.get(outputDiff).add(outputPair);
        });
        return outPairs;
    }

    private List<String> replaceUnknownBits(String diff) {
        List<String> result = new ArrayList<>();
        int index = diff.indexOf('x');
        if (index == -1) {
            result.add(diff);
        } else {
            char[] chars = diff.toCharArray();
            chars[index] = '0';
            result.add(String.valueOf(chars));
            chars[index] = '1';
            result.add(String.valueOf(chars));
        }
        return result;
    }

    private List<Integer> getBlockNumbersForAnalysis(List<String> inputDiffBlocks,
                                                     List<String> outputDiffBlocks) {
        List<Integer> numbers = new ArrayList<>();
        for (int i = 0; i < inputDiffBlocks.size(); i++) {
            String inDiff = inputDiffBlocks.get(i);
            String outDiff = outputDiffBlocks.get(i);
            List<Integer> indicesOfUnknown = indicesOf(inDiff, 'x');
            if (!isZero(inDiff) &&
                    !isZero(outDiff) &&
                    indicesOfUnknown.size() < 2) {
                numbers.add(i);
            }
        }
        return numbers;
    }

    private String getSBoxOutputDifference(String inputDifferenceBlock) {
        StringBuilder result = new StringBuilder();
        for (String input : Splitter.fixedLength(spn.getSBoxInputSize()).split(inputDifferenceBlock)) {
            List<String> outputDiff = input.indexOf('x') == -1 ?
                    getOutputDifferences(input) : getUniqueOutputDifferences(input);
            char[] output = outputDiff.get(0).toCharArray();
            IntStream
                    .range(1, outputDiff.size())
                    .mapToObj(i -> xor(outputDiff.get(i - 1), outputDiff.get(i)))
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
            String number = valueOf(i, length);
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
