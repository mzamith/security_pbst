package org.feup.ses.pbst.Enums;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public enum TestResultEnum {

    NOT_TESTED(0, "Not Tested"),
    SECURE(1, "Secure"),
    VULNERABLE(2, "Vulnerable");

    public static final int NOT_TESTED_VALUE = 0;
    public static final int SECURE_VALUE = 1;
    public static final int VULNERABLE_VALUE = 2;

    private static final TestResultEnum[] VALUES_ARRAY = new TestResultEnum[]{NOT_TESTED, SECURE, VULNERABLE};

    public static TestResultEnum get(int value) {
        switch (value) {
            case NOT_TESTED_VALUE:
                return NOT_TESTED;
            case SECURE_VALUE:
                return SECURE;
            case VULNERABLE_VALUE:
                return VULNERABLE;
        }
        return null;
    }

    public static final List<TestResultEnum> VALUES = Collections.unmodifiableList(Arrays.asList(VALUES_ARRAY));

    public static TestResultEnum get(String literal) {
        for (int i = 0; i < VALUES_ARRAY.length; ++i) {
            TestResultEnum result = VALUES_ARRAY[i];
            if (result.toString().equals(literal)) {
                return result;
            }
        }
        return null;
    }

    public static TestResultEnum getByName(String name) {
        for (int i = 0; i < VALUES_ARRAY.length; ++i) {
            TestResultEnum result = VALUES_ARRAY[i];
            if (result.getName().equals(name)) {
                return result;
            }
        }
        return null;
    }

    private final int value;
    private final String name;

    private TestResultEnum(int value, String name) {
        this.value = value;
        this.name = name;
    }

    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }
}
