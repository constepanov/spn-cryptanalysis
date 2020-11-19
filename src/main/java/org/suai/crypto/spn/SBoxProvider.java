package org.suai.crypto.spn;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import static org.suai.crypto.util.BinaryString.valueOf;

public class SBoxProvider {
    public static BidiMap<String, String> readFromFile(File file, int binaryLength) throws IOException {
        List<String> lines = Files.readAllLines(file.toPath());
        BidiMap<String, String> sBox = new DualHashBidiMap<>();
        lines.stream().map(line -> line.split(" ")).forEach(s -> {
            int input = Integer.parseInt(s[0]);
            int output = Integer.parseInt(s[1]);
            sBox.put(valueOf(input, binaryLength), valueOf(output, binaryLength));
        });
        return sBox;
    }
}
