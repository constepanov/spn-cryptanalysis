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
                    String key = entry.getKey();
                    String value = entry.getValue();

                    int inputCombination = IntStream.range(0, inputMask.length())
                            .map(k -> (int) inputMask.charAt(k) & (int) key.charAt(k))
                            .reduce(0, (a, b) -> a ^ b);

                    int outputCombination = IntStream.range(0, outputMask.length())
                            .map(k -> (int) outputMask.charAt(k) & (int) value.charAt(k))
                            .reduce(0, (a, b) -> a ^ b);

                    if (inputCombination == outputCombination) {
                        numberOfMatches++;
                    }
                }
                table[i][j] = numberOfMatches;
            }
        }
        return table;
    }
}
