package org.suai.crypto.spn;

import com.google.common.base.Splitter;
import org.apache.commons.collections4.BidiMap;
import org.suai.crypto.util.BinaryString;

public class SubstitutionPermutationNetwork {

    private static final int BLOCK_SIZE = 9;
    private static final int NUMBER_OF_ROUNDS = 3;
    private static final int S_BOX_INPUT_SIZE = 3;
    private static final int[] BIT_PERMUTATION = {0, 3, 6, 1, 4, 7, 2, 5, 8};

    private BidiMap<String, String> sBox;

    public SubstitutionPermutationNetwork(BidiMap<String, String> sBox) {
        this.sBox = sBox;
    }

    public String encrypt(String plaintext, String key) {
        String sBoxInput = BinaryString.xor(plaintext, key);
        String sBoxOutput = applySBox(sBoxInput);
        String permutationOutput = BinaryString.permute(sBoxOutput, BIT_PERMUTATION);

        sBoxInput = BinaryString.xor(permutationOutput, key);
        sBoxOutput = applySBox(sBoxInput);
        permutationOutput = BinaryString.permute(sBoxOutput, BIT_PERMUTATION);

        sBoxInput = BinaryString.xor(permutationOutput, key);
        sBoxOutput = applySBox(sBoxInput);
        sBoxInput = BinaryString.xor(sBoxOutput, key);
        return sBoxInput;
    }

    public String decrypt(String ciphertext, String key) {
        String sBoxInput = BinaryString.xor(ciphertext, key);
        String sBoxOutput = applyInverseSBox(sBoxInput);
        String permutationInput = BinaryString.xor(sBoxOutput, key);

        sBoxInput = BinaryString.permute(permutationInput, BIT_PERMUTATION);
        sBoxOutput = applyInverseSBox(sBoxInput);
        permutationInput = BinaryString.xor(sBoxOutput, key);

        sBoxInput = BinaryString.permute(permutationInput, BIT_PERMUTATION);
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

    public BidiMap<String, String> getSBox() {
        return sBox;
    }

    public void setSBox(BidiMap<String, String> sBox) {
        this.sBox = sBox;
    }

    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    public int getNumberOfRounds() {
        return NUMBER_OF_ROUNDS;
    }

    public int getSBoxInputSize() {
        return S_BOX_INPUT_SIZE;
    }

    public int[] getBitPermutation() {
        return BIT_PERMUTATION;
    }
}
