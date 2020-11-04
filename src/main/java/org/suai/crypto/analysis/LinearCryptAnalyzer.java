package org.suai.crypto.analysis;

import com.google.common.base.Splitter;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.IterableUtils;
import org.suai.crypto.util.BinaryString;
import org.suai.crypto.util.EquationElement;
import org.suai.crypto.util.EquationElementType;
import org.suai.crypto.util.LinearApproximation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.suai.crypto.spn.SPNConstants.BIT_PERMUTATION;
import static org.suai.crypto.spn.SPNConstants.S_BOX_INPUT_SIZE;
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
                double probability = (double) table[row][column] / maxNumberOfMatches;
                roundApproximations.add(new LinearApproximation(leftPart, rightPart, probability));
            } else {
                roundOutputs.add(BinaryString.valueOf(0, S_BOX_INPUT_SIZE));
            }
        }
        return roundApproximations;
    }

    private static List<String> getRoundInputs(String block) {
        return IterableUtils.toList(Splitter
                .fixedLength(S_BOX_INPUT_SIZE)
                .split(block));
    }

    public static List<LinearApproximation> buildSPNApproximation(int[][] table, String inputBlock) {

        int roundNumber = 1;
        List<String> firstRoundOutputs = new ArrayList<>();
        List<String> secondRoundOutputs = new ArrayList<>();
        List<String> thirdRoundOutputs = new ArrayList<>();

        List<String> firstRoundInputs = getRoundInputs(inputBlock);

        List<LinearApproximation> firstRoundApproximations = getRoundApproximations(table,
                roundNumber,
                firstRoundInputs,
                firstRoundOutputs);
        System.out.println(firstRoundApproximations);
        simplifyRightPartInFirstRoundApproximations(firstRoundApproximations);
        System.out.println(firstRoundApproximations);

        roundNumber = 2;
        String secondRoundBlock = BinaryString.permute(String.join("", firstRoundOutputs), BIT_PERMUTATION);
        List<String> secondRoundInputs = getRoundInputs(secondRoundBlock);

        List<LinearApproximation> secondRoundApproximations = getRoundApproximations(table,
                roundNumber,
                secondRoundInputs,
                secondRoundOutputs);
        System.out.println(secondRoundApproximations);
        simplifyRightPartInRoundApproximations(secondRoundApproximations);
        System.out.println(secondRoundApproximations);

        roundNumber = 3;
        String thirdRoundBlock = BinaryString.permute(String.join("", secondRoundOutputs), BIT_PERMUTATION);
        List<String> thirdRoundInputs = getRoundInputs(thirdRoundBlock);

        List<LinearApproximation> thirdRoundApproximations = getRoundApproximations(table,
                roundNumber,
                thirdRoundInputs,
                thirdRoundOutputs);
        System.out.println(thirdRoundApproximations);
        simplifyRightPartInRoundApproximations(thirdRoundApproximations);
        System.out.println(thirdRoundApproximations);
        simplifyLeftPartInThirdRoundApproximations(thirdRoundApproximations);
        System.out.println(thirdRoundApproximations);

        LinearApproximation resultApproximation = null;
        List<List<LinearApproximation>> approximations = Arrays.asList(firstRoundApproximations,
                secondRoundApproximations,
                thirdRoundApproximations);
        for (List<LinearApproximation> roundApproximations : approximations) {
            if (roundApproximations.size() == 1) {
                resultApproximation = roundApproximations.get(0);
                break;
            }
        }

        if (resultApproximation == null) {
            throw new RuntimeException("Can't build linear approximation with this input");
        }

        // Now we must build one final approximation
        for (EquationElement element : resultApproximation.getLeftPart()) {
            for (List<LinearApproximation> roundApproximations : approximations) {
                LinearApproximation replacementEquation = resultApproximation.moveToLeft(element);
            }
        }

        return thirdRoundApproximations;
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

    private static void simplifyLeftPartInThirdRoundApproximations(List<LinearApproximation> roundApproximations) {
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

    public static int getTableColumn(int[][] table, int row) {
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
