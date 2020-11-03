package org.suai.crypto.analysis;

import org.apache.commons.collections4.BidiMap;
import org.suai.crypto.util.BinaryString;

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
}
