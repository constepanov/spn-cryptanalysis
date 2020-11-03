package org.suai.crypto.util;

import com.google.common.base.Strings;

import java.util.function.IntFunction;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class BinaryString {

    public static String xor(String first, String second) {
        return applyBitOperation(first.length(), i -> String.valueOf((int) first.charAt(i) ^ (int) second.charAt(i)));
    }

    public static String and(String first, String second) {
        return applyBitOperation(first.length(), i -> String.valueOf((int) first.charAt(i) & (int) second.charAt(i)));
    }

    private static String applyBitOperation(int length, IntFunction<String> operation) {
        return IntStream
                .range(0, length)
                .mapToObj(operation)
                .collect(Collectors.joining());
    }

    public static String valueOf(int value, int length) {
        return Strings.padStart(Integer.toBinaryString(value), length, '0');
    }
}
