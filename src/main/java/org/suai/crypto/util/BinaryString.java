package org.suai.crypto.util;

import com.google.common.base.Strings;

import java.security.SecureRandom;
import java.util.function.IntFunction;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.lang.Character.getNumericValue;

public class BinaryString {

    private BinaryString() {}

    public static String xor(String first, String second) {
        return applyBitOperation(first.length(),
                i -> String.valueOf(getNumericValue(first.charAt(i)) ^ getNumericValue(second.charAt(i))));
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

    public static String permute(String block, int[] bitPermutation) {
        char[] result = new char[block.length()];
        IntStream.range(0, block.length())
                .forEach(i -> result[bitPermutation[i]] = block.charAt(i));
        return String.valueOf(result);
    }

    public static boolean isZero(String value) {
        return value.equals(valueOf(0, value.length()));
    }

    public static String random(int length) {
        SecureRandom random = new SecureRandom();
        return IntStream.range(0, length)
                .mapToObj(i -> String.valueOf(Math.abs(random.nextInt() % 2)))
                .collect(Collectors.joining());
    }
}
