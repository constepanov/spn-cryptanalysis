package org.suai.crypto.spn;

import com.google.common.base.Splitter;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class SubstitutionPermutationNetwork {

    private final int S_BOX_INPUT_SIZE = 3;
    private final int[] bitPermutation = {0, 3, 6, 1, 4, 7, 2, 5, 8};
    private final BidiMap<String, String> sBox;

    public SubstitutionPermutationNetwork() {
        this.sBox = new DualHashBidiMap<>();
        initSBox();
    }

    private void initSBox() {
        sBox.put("000", "110");
        sBox.put("001", "111");
        sBox.put("010", "100");
        sBox.put("011", "011");
        sBox.put("100", "010");
        sBox.put("101", "101");
        sBox.put("110", "001");
        sBox.put("111", "000");
    }

    public String encrypt(String plaintext, String key) {
        String sBoxInput = xorBitString(plaintext, key);
        String sBoxOutput = applySBox(sBoxInput);
        String permutationOutput = permuteString(sBoxOutput);

        sBoxInput = xorBitString(permutationOutput, key);
        sBoxOutput = applySBox(sBoxInput);
        permutationOutput = permuteString(sBoxOutput);

        sBoxInput = xorBitString(permutationOutput, key);
        sBoxOutput = applySBox(sBoxInput);
        sBoxInput = xorBitString(sBoxOutput, key);
        return sBoxInput;
    }

    public String decrypt(String ciphertext, String key) {
        String sBoxInput = xorBitString(ciphertext, key);
        String sBoxOutput = applyInverseSBox(sBoxInput);
        String permutationInput = xorBitString(sBoxOutput, key);

        sBoxInput = permuteString(permutationInput);
        sBoxOutput = applyInverseSBox(sBoxInput);
        permutationInput = xorBitString(sBoxOutput, key);

        sBoxInput = permuteString(permutationInput);
        sBoxOutput = applyInverseSBox(sBoxInput);
        permutationInput = xorBitString(sBoxOutput, key);
        return permutationInput;
    }

    private String applySBox(String block) {
        StringBuilder result = new StringBuilder();
        for (String input : Splitter.fixedLength(S_BOX_INPUT_SIZE).split(block)) {
            result.append(sBox.get(input));
        }
        return result.toString();
    }

    private String applyInverseSBox(String block) {
        StringBuilder result = new StringBuilder();
        for (String input : Splitter.fixedLength(S_BOX_INPUT_SIZE).split(block)) {
            result.append(sBox.getKey(input));
        }
        return result.toString();
    }

    public String xorBitString(String block, String key) {
        return IntStream
                .range(0, block.length())
                .mapToObj(i -> String.valueOf((int) block.charAt(i) ^ (int) key.charAt(i)))
                .collect(Collectors.joining());
    }

    public String permuteString(String block) {
        char[] result = new char[block.length()];
        IntStream.range(0, block.length())
                .forEach(i -> result[bitPermutation[i]] = block.charAt(i));
        return String.valueOf(result);
    }
}
