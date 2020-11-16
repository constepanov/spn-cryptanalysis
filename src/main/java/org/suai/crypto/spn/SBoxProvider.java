package org.suai.crypto.spn;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

public class SBoxProvider {
    public static BidiMap<String, String> getForDiffAnalysis() {
        BidiMap<String, String> sBox = new DualHashBidiMap<>();
        sBox.put("000", "110");
        sBox.put("001", "000");
        sBox.put("010", "101");
        sBox.put("011", "001");
        sBox.put("100", "111");
        sBox.put("101", "011");
        sBox.put("110", "100");
        sBox.put("111", "010");
        return sBox;
    }

    public static BidiMap<String, String> getForLinearAnalysis() {
        BidiMap<String, String> sBox = new DualHashBidiMap<>();
        sBox.put("000", "111");
        sBox.put("001", "110");
        sBox.put("010", "011");
        sBox.put("011", "010");
        sBox.put("100", "000");
        sBox.put("101", "001");
        sBox.put("110", "101");
        sBox.put("111", "100");
        return sBox;
    }
}
