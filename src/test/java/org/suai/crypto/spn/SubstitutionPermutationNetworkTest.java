package org.suai.crypto.spn;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SubstitutionPermutationNetworkTest {

    @Test
    void testSuccessDecrypt() {
        String plaintext = "101001111";
        String key = "101010100";
        SubstitutionPermutationNetwork spn = new SubstitutionPermutationNetwork();
        String ciphertext = spn.encrypt(plaintext, key);
        String decrypted = spn.decrypt(ciphertext, key);
        Assertions.assertEquals(plaintext, decrypted);
    }
}
