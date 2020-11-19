package org.suai.crypto.util;

import lombok.Data;
import org.apache.commons.math3.util.Pair;

@Data
public class TextPair {
    private Pair<String, String> plaintextPair;
    private Pair<String, String> ciphertextPair;
}
