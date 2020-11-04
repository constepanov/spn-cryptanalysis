package org.suai.crypto.analysis;

import com.google.common.base.Splitter;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.IterableUtils;
import org.suai.crypto.util.BinaryString;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.suai.crypto.spn.SPNConstants.S_BOX_INPUT_SIZE;

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

    public static void buildRandomSPNApproximations(int[][] table) {

    }

    public static void buildSPNApproximation(int[][] table, String inputBits) {
        // Предположим, что входной бит 7, то есть inputBits[6] = 1 или inputBits[0] = 6
        // Для каждого раунда может быть построено максимум 3 уравнения
        // Далее необходимо их объединить так, чтобы в них были только X и Y
        List<String> firstRoundInputs = IterableUtils.toList(Splitter.fixedLength(S_BOX_INPUT_SIZE).split(inputBits));
        firstRoundInputs.removeIf(BinaryString::isZero);
        List<String> firstRoundOutputs = new ArrayList<>();
        for (String roundInput : firstRoundInputs) {
            int i = Integer.parseInt(roundInput, 2);
            // нужно подумать каким образом получать j
            int j = Arrays.stream(table[i]).min().getAsInt();
            firstRoundOutputs.add(BinaryString.valueOf(table[i][j], S_BOX_INPUT_SIZE));
        }

        // 000000101 = 000000100
        // 000000100 =
        /*
        List<RoundEquation> firstRoundEquations;
        for (String roundInput : firstRoundInputs) {
            if (!roundInput.equals(BinaryString.valueOf(0, S_BOX_INPUT_SIZE))) {
                firstRoundEquations.add(equation);
            }
        }
         */

    }
}
