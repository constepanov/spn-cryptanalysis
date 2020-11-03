package org.suai.crypto.spn;

import com.google.common.base.Splitter;
import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;
import org.suai.crypto.util.BinaryString;

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
        /*
        sBox.put("000", "110");
        sBox.put("001", "111");
        sBox.put("010", "100");
        sBox.put("011", "011");
        sBox.put("100", "010");
        sBox.put("101", "101");
        sBox.put("110", "001");
        sBox.put("111", "000");
         */


        // S-box from example
        sBox.put("000", "111");
        sBox.put("001", "001");
        sBox.put("010", "100");
        sBox.put("011", "000");
        sBox.put("100", "110");
        sBox.put("101", "010");
        sBox.put("110", "101");
        sBox.put("111", "011");
    }

    public String encrypt(String plaintext, String key) {
        String sBoxInput = BinaryString.xor(plaintext, key);
        String sBoxOutput = applySBox(sBoxInput);
        String permutationOutput = permuteString(sBoxOutput);

        sBoxInput = BinaryString.xor(permutationOutput, key);
        sBoxOutput = applySBox(sBoxInput);
        permutationOutput = permuteString(sBoxOutput);

        sBoxInput = BinaryString.xor(permutationOutput, key);
        sBoxOutput = applySBox(sBoxInput);
        sBoxInput = BinaryString.xor(sBoxOutput, key);
        return sBoxInput;
    }

    public String decrypt(String ciphertext, String key) {
        String sBoxInput = BinaryString.xor(ciphertext, key);
        String sBoxOutput = applyInverseSBox(sBoxInput);
        String permutationInput = BinaryString.xor(sBoxOutput, key);

        sBoxInput = permuteString(permutationInput);
        sBoxOutput = applyInverseSBox(sBoxInput);
        permutationInput = BinaryString.xor(sBoxOutput, key);

        sBoxInput = permuteString(permutationInput);
        sBoxOutput = applyInverseSBox(sBoxInput);
        permutationInput = BinaryString.xor(sBoxOutput, key);
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

    public String permuteString(String block) {
        char[] result = new char[block.length()];
        IntStream.range(0, block.length())
                .forEach(i -> result[bitPermutation[i]] = block.charAt(i));
        return String.valueOf(result);
    }

    public BidiMap<String, String> getSBox() {
        return sBox;
    }
}
