package me.bechberger.fuzz.util;

import picocli.CommandLine;

public class DurationConverter implements CommandLine.ITypeConverter<Long> {
    @Override
    public Long convert(String value) {
        return parseToNanoSeconds(value);
    }

    /**
     * Parse any duration string to time, support "s" and "ms" and fractions and fractions
     */
    static long parseToNanoSeconds(String text) {
        if (!text.matches("[0-9]+(\\.[0-9]+)?(ms|us|ns|s)")) {
            throw new IllegalArgumentException("Invalid duration string: " + text);
        }
        int unit = 1_000_000_000;
        int unitLength = 2;
        if (text.endsWith("ms")) {
            unit = 1_000_000;
        } else if (text.endsWith("us")) {
            unit = 1_000;
        } else if (text.endsWith("ns")) {
            unit = 1;
        } else {
            unitLength = 1;
        }
        return (long) (Double.parseDouble(text.substring(0, text.length() - unitLength)) * unit);
    }

    public static String nanoSecondsToString(long nanoSeconds, int decimals) {
        if (nanoSeconds < 1_000) {
            return nanoSeconds + "ns";
        } else if (nanoSeconds < 1_000_000) {
            return String.format("%." + decimals + "fus", nanoSeconds / 1_000.0);
        } else if (nanoSeconds < 1_000_000_000) {
            return String.format("%." + decimals + "fms", nanoSeconds / 1_000_000.0);
        } else {
            return String.format("%." + decimals + "fs", nanoSeconds / 1_000_000_000.0);
        }
    }
}
