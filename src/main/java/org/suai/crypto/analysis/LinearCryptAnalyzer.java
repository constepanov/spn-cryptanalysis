package org.suai.crypto.analysis;

import org.apache.commons.collections4.BidiMap;
import org.suai.crypto.util.BinaryString;

import java.util.Map;
import java.util.stream.IntStream;

public class LinearCryptAnalyzer {

    public static int[][] buildApproximationTable(BidiMap<String, String> sBox) {
        int[][] table = new int[7][7];
        for (int i = 0; i < 7; i++) {
            for (int j = 0; j < 7; j++) {
                int numberOfMatches = 0;
                String inputMask = BinaryString.valueOf(i + 1, 3);
                String outputMask = BinaryString.valueOf(j + 1, 3);
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
