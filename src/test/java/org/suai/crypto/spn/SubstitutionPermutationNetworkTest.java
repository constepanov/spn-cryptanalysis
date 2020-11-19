package org.suai.crypto.spn;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SubstitutionPermutationNetworkTest {

    @Test
    void testSuccessDecrypt() {
        String plaintext = "101001111";
        String key = "101010100";
        BidiMap<String, String> sBox = new DualHashBidiMap<>();
        sBox.put("000", "111");
        sBox.put("001", "110");
        sBox.put("010", "011");
        sBox.put("011", "010");
        sBox.put("100", "000");
        sBox.put("101", "001");
        sBox.put("110", "101");
        sBox.put("111", "100");
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork(sBox);
        String ciphertext = spn.encrypt(plaintext, key);
        String decrypted = spn.decrypt(ciphertext, key);
        Assertions.assertEquals(plaintext, decrypted);
    }
}
