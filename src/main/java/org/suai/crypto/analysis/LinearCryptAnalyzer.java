package org.suai.crypto.analysis;

import com.google.common.base.Splitter;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.math3.fraction.Fraction;
import org.suai.crypto.spn.SubstitutionPermutationNetwork;
import org.suai.crypto.util.BinaryString;
import org.suai.crypto.util.EquationElement;
import org.suai.crypto.util.EquationElementType;
import org.suai.crypto.util.LinearApproximation;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.lang.Character.*;
import static org.suai.crypto.spn.SPNConstants.*;
import static org.suai.crypto.util.EquationElementType.*;

public class LinearCryptAnalyzer {

    public static int[][] buildApproximationTable(BidiMap<String, String> sBox) {
        int tableSize = (int) (Math.pow(2, S_BOX_INPUT_SIZE) - 1);
        int[][] table = new int[tableSize][tableSize];
        for (int i = 0; i < tableSize; i++) {
            for (int j = 0; j < tableSize; j++) {
                int numberOfMatches = 0;
                String inputMask = BinaryString.valueOf(i + 1, S_BOX_INPUT_SIZE);
                String outputMask = BinaryString.valueOf(j + 1, S_BOX_INPUT_SIZE);
                for (Map.Entry<String, String> entry : sBox.entrySet()) {
                    String sBoxInput = entry.getKey();
                    String sBoxOutput = entry.getValue();

                    int inputCombination = getCombinationResult(inputMask, sBoxInput);
                    int outputCombination = getCombinationResult(outputMask, sBoxOutput);

                    if (inputCombination == outputCombination) {
                        numberOfMatches++;
                    }
                }
                table[i][j] = numberOfMatches;
            }
        }
        return table;
    }

    private static int getCombinationResult(String mask, String value) {
        return IntStream.range(0, mask.length())
                .map(i -> (int) mask.charAt(i) & (int) value.charAt(i))
                .reduce(0, (a, b) -> a ^ b);
    }

    public static Map<String, String> generateCiphertextAndPlaintext(int count, String key) {
        Map<String, String> pairs = new HashMap<>();
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork();
        for (int i = 0; i < count; i++) {
            String plaintext = BinaryString.random(BLOCK_SIZE);
            String ciphertext = spn.encrypt(plaintext, key);
            pairs.put(plaintext, ciphertext);
        }
        return pairs;
    }

    public static double getApproximationLeftPartStats(LinearApproximation approximation, Map<String, String> pairs) {
        int leftPartEqualsOneCount = 0;
        for (Map.Entry<String, String> entry : pairs.entrySet()) {
            String plaintext = entry.getKey();
            String ciphertext = entry.getValue();
            int result = 0;
            for (EquationElement element : approximation.getLeftPart()) {
                int bitIndex = element.getBitNumber() - 1;
                result ^= element.getType() == CIPHERTEXT ? getNumericValue(ciphertext.charAt(bitIndex))
                        : getNumericValue(plaintext.charAt(bitIndex));
            }
            if (result == 1) {
                leftPartEqualsOneCount++;
            }
        }
        return (double) leftPartEqualsOneCount / pairs.size();
    }

    private static int getRightPartDecision(LinearApproximation approximation, int leftPartDecision) {
        return approximation.getProbability()
                .compareTo(Fraction.ONE_HALF) > 0 ? leftPartDecision : leftPartDecision ^ 1;
    }

    public static List<LinearApproximation> getKeyEquations(List<LinearApproximation> approximations,
                                                            Map<String, String> pairs) {
        List<LinearApproximation> keyEquations = new ArrayList<>();
        for (LinearApproximation approximation : approximations) {
            double leftPartStats = getApproximationLeftPartStats(approximation, pairs);
            int leftPartDecision = leftPartStats > 0.5 ? 1 : 0;
            int rightPartDecision = getRightPartDecision(approximation, leftPartDecision);
            LinearApproximation keyEquation = new LinearApproximation();
            keyEquation.setLeftPart(approximation.getRightPart());
            EquationElement rightElement = new EquationElement(rightPartDecision == 1 ? ONE : ZERO);
            keyEquation.addToRight(rightElement);
            keyEquation.setProbability(Fraction.ONE);
            keyEquations.add(keyEquation);
        }
        return keyEquations;
    }

    public static List<LinearApproximation> getSPNApproximations(int[][] table, List<String> inputBlocks) {
        List<LinearApproximation> result = new ArrayList<>();
        for (String inputBlock : inputBlocks) {
            result.add(getSPNApproximation(table, inputBlock));
        }
        return result;
    }

    public static LinearApproximation getSPNApproximation(int[][] table, String inputBlock) {
        Map<Integer, List<LinearApproximation>> approximations = new LinkedHashMap<>();

        List<String> firstRoundInputs = getRoundInputs(inputBlock);
        List<String> roundOutputs = new ArrayList<>();
        List<LinearApproximation> firstRoundApproximations = getRoundApproximations(table,
                1,
                firstRoundInputs,
                roundOutputs);
        System.out.println(firstRoundApproximations);
        simplifyRightPartInFirstRoundApproximations(firstRoundApproximations);
        System.out.println(firstRoundApproximations);
        approximations.put(1, firstRoundApproximations);

        for (int i = 1; i < NUMBER_OF_ROUNDS; i++) {
            int roundNumber = i + 1;
            String roundBlock = BinaryString.permute(String.join("", roundOutputs), BIT_PERMUTATION);
            List<String> roundInputs = getRoundInputs(roundBlock);
            roundOutputs.clear();
            List<LinearApproximation> roundApproximations = getRoundApproximations(table,
                    roundNumber,
                    roundInputs,
                    roundOutputs);
            System.out.println(roundApproximations);
            simplifyRightPartInRoundApproximations(roundApproximations);
            System.out.println(roundApproximations);
            if (i == NUMBER_OF_ROUNDS - 1) {
                simplifyLeftPartInLastRoundApproximations(roundApproximations);
                System.out.println(roundApproximations);
            }
            approximations.put(roundNumber, roundApproximations);
        }

        Map.Entry<Integer, List<LinearApproximation>> resultEntry = approximations.entrySet()
                .stream()
                .filter((entry) -> entry.getValue().size() == 1)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Can't build linear approximation with this input"));
        LinearApproximation resultApproximation = resultEntry.getValue().get(0);
        int resultApproximationRoundNumber = resultEntry.getKey();

        // Now we must combine round approximations into final approximation

        List<LinearApproximation> usedApproximations = new ArrayList<>();
        usedApproximations.add(resultApproximation);

        int leftIterations = NUMBER_OF_ROUNDS - resultApproximationRoundNumber;
        int rightIterations = NUMBER_OF_ROUNDS - leftIterations - 1;

        for (int i = 0; i < leftIterations; i++) {
            List<EquationElement> updatedLeftPart = new ArrayList<>();
            List<EquationElement> replacedElements = new ArrayList<>();
            for (EquationElement element : resultApproximation.getLeftPart()) {
                if (element.getType() == PLAINTEXT || element.getType() == CIPHERTEXT || element.getType() == KEY) {
                    continue;
                }
                int approximationIndex = element.getRoundNumber() + 1;
                List<LinearApproximation> roundApproximations = approximations.get(approximationIndex);
                for (LinearApproximation approximation : roundApproximations) {
                    if (approximation.getRightPart().contains(element) && !usedApproximations.contains(approximation)) {
                        LinearApproximation replacementEquation = approximation.moveToLeft(element);
                        LinearApproximation temp = new LinearApproximation();
                        temp.addToLeft(element);
                        temp = temp.replaceInLeft(replacementEquation);
                        updatedLeftPart.addAll(temp.getLeftPart());
                        usedApproximations.add(approximation);
                        replacedElements.add(element);
                    }
                }
            }
            resultApproximation.getLeftPart()
                    .stream()
                    .filter(element -> !replacedElements.contains(element))
                    .forEach(updatedLeftPart::add);
            resultApproximation.setLeftPart(updatedLeftPart);
            System.out.println(resultApproximation);
        }

        for (int i = 0; i < rightIterations; i++) {
            List<EquationElement> updatedRightPart = new ArrayList<>();
            List<EquationElement> replacedElements = new ArrayList<>();
            for (EquationElement element : resultApproximation.getRightPart()) {
                if (element.getType() == PLAINTEXT || element.getType() == CIPHERTEXT || element.getType() == KEY) {
                    continue;
                }
                int approximationIndex = element.getRoundNumber();
                List<LinearApproximation> roundApproximations = approximations.get(approximationIndex);
                for (LinearApproximation approximation : roundApproximations) {
                    if (approximation.getLeftPart().contains(element) && !usedApproximations.contains(approximation)) {
                        LinearApproximation replacementEquation = approximation.moveToLeft(element);
                        LinearApproximation temp = new LinearApproximation();
                        temp.addToLeft(element);
                        temp = temp.replaceInLeft(replacementEquation);
                        updatedRightPart.addAll(temp.getLeftPart());
                        usedApproximations.add(approximation);
                        replacedElements.add(element);
                    }
                }
            }
            resultApproximation.getRightPart()
                    .stream()
                    .filter(element -> !replacedElements.contains(element))
                    .forEach(updatedRightPart::add);
            resultApproximation.setRightPart(updatedRightPart);
            System.out.println(resultApproximation);
        }

        resultApproximation.simplify();
        System.out.println(resultApproximation);
        resultApproximation.transformToStandardForm();

        Fraction resultProbability = getSPNApproximationProbability(approximations);
        resultApproximation.setProbability(resultProbability);
        System.out.println("Final approximation: " + resultApproximation);

        return resultApproximation;
    }

    private static List<String> getRoundInputs(String block) {
        return IterableUtils.toList(Splitter
                .fixedLength(S_BOX_INPUT_SIZE)
                .split(block));
    }

    private static List<LinearApproximation> getRoundApproximations(int[][] table,
                                                                    int roundNumber,
                                                                    List<String> roundInputs,
                                                                    List<String> roundOutputs) {
        int maxNumberOfMatches = (int) Math.pow(2, S_BOX_INPUT_SIZE);
        List<LinearApproximation> roundApproximations = new ArrayList<>();
        for (int i = 0; i < roundInputs.size(); i++) {
            String roundInput = roundInputs.get(i);
            if (!BinaryString.isZero(roundInput)) {
                int row = Integer.parseInt(roundInput, 2) - 1;
                int column = getTableColumn(table, row);
                String sBoxOutput = BinaryString.valueOf(column + 1, S_BOX_INPUT_SIZE);
                roundOutputs.add(sBoxOutput);
                List<EquationElement> leftPart = getApproximationPart(roundNumber, i, sBoxOutput, S_BOX_OUTPUT);
                List<EquationElement> rightPart = getApproximationPart(roundNumber, i, roundInput, S_BOX_INPUT);
                Fraction probability = new Fraction(table[row][column], maxNumberOfMatches);
                roundApproximations.add(new LinearApproximation(leftPart, rightPart, probability));
            } else {
                roundOutputs.add(BinaryString.valueOf(0, S_BOX_INPUT_SIZE));
            }
        }
        return roundApproximations;
    }

    private static void simplifyRightPartInFirstRoundApproximations(List<LinearApproximation> firstRoundApproximations) {
        for (LinearApproximation approximation : firstRoundApproximations) {
            List<EquationElement> rightPart = approximation.getRightPart();
            List<EquationElement> updatedRightPart = new ArrayList<>();
            for (EquationElement element : rightPart) {
                updatedRightPart.add(new EquationElement(element.getBitNumber(), PLAINTEXT));
                updatedRightPart.add(new EquationElement(element.getBitNumber(), KEY));
            }
            approximation.setRightPart(updatedRightPart);
        }
    }

    private static void simplifyRightPartInRoundApproximations(List<LinearApproximation> roundApproximations) {
        for (LinearApproximation approximation : roundApproximations) {
            List<EquationElement> rightPart = approximation.getRightPart();
            List<EquationElement> updatedRightPart = new ArrayList<>();
            for (EquationElement element : rightPart) {
                int bitNumber = BIT_PERMUTATION[element.getBitNumber() - 1] + 1;
                int roundNumber = element.getRoundNumber() - 1;
                updatedRightPart.add(new EquationElement(roundNumber, bitNumber, S_BOX_OUTPUT));
                updatedRightPart.add(new EquationElement(element.getBitNumber(), KEY));
            }
            approximation.setRightPart(updatedRightPart);
        }
    }

    private static void simplifyLeftPartInLastRoundApproximations(List<LinearApproximation> roundApproximations) {
        for (LinearApproximation approximation : roundApproximations) {
            List<EquationElement> leftPart = approximation.getLeftPart();
            List<EquationElement> updatedLeftPart = new ArrayList<>();
            for (EquationElement element : leftPart) {
                updatedLeftPart.add(new EquationElement(element.getBitNumber(), CIPHERTEXT));
                updatedLeftPart.add(new EquationElement(element.getBitNumber(), KEY));
            }
            approximation.setLeftPart(updatedLeftPart);
        }
    }

    private static List<EquationElement> getApproximationPart(int roundNumber, int sBoxIndex, String value, EquationElementType type) {
        return IntStream.range(0, value.length())
                .filter(i -> value.charAt(i) != '0')
                .map(i -> sBoxIndex * S_BOX_INPUT_SIZE + i + 1)
                .mapToObj(bitNumber -> new EquationElement(roundNumber, bitNumber, type))
                .collect(Collectors.toList());
    }

    private static Fraction getSPNApproximationProbability(Map<Integer, List<LinearApproximation>> approximations) {
        // Piling-Up Lemma
        int n = approximations.values().stream().mapToInt(List::size).sum();
        Fraction probability = new Fraction(Math.pow(2, n - 1));
        for (List<LinearApproximation> roundApproximations : approximations.values()) {
            for (LinearApproximation approximation : roundApproximations) {
                Fraction factor = approximation.getProbability().subtract(Fraction.ONE_HALF);
                probability = probability.multiply(factor);
            }
        }
        return Fraction.ONE_HALF.add(probability);
    }

    public static int getTableColumn(int[][] table, int row) {
        // Should this function return min or max?
        int minIndex = indexOfMin(table[row]);
        if (table[row][minIndex] == 0) {
            return minIndex;
        }
        int maxIndex = indexOfMax(table[row]);
        if (table[row][maxIndex] == 8) {
            return maxIndex;
        }
        return minIndex;
    }

    private static int indexOfMin(int[] array) {
        int index = 0;
        int min = array[index];
        for (int i = 1; i < array.length; i++){
            if (array[i] < min) {
                min = array[i];
                index = i;
            }
        }
        return index;
    }

    private static int indexOfMax(int[] array) {
        int index = 0;
        int max = array[index];
        for (int i = 1; i < array.length; i++) {
            if (array[i] > max) {
                max = array[i];
                index = i;
            }
        }
        return index;
    }
}
