package org.feup.ses.pbst.Enums;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.feup.ses.pbst.Interfaces.Enumerator;

public enum AccessLevel implements Enumerator {

    LEVEL_0(0, "Level_0", "Level 0 - Total Access"),
    LEVEL_1(1, "Level_1", "Level 1"),
    LEVEL_2(2, "Level_2", "Level 2"),
    LEVEL_3(3, "Level_3", "Level 3"),
    LEVEL_4(4, "Level_4", "Level 4"),
    LEVEL_5(5, "Level_5", "Level 5 - Very Restrictive");

    public static final int LEVEL_0_VALUE = 0;
    public static final int LEVEL_1_VALUE = 1;
    public static final int LEVEL_2_VALUE = 2;
    public static final int LEVEL_3_VALUE = 3;
    public static final int LEVEL_4_VALUE = 4;
    public static final int LEVEL_5_VALUE = 5;

    private static final AccessLevel[] VALUES_ARRAY
            = new AccessLevel[]{
                LEVEL_0,
                LEVEL_1,
                LEVEL_2,
                LEVEL_3,
                LEVEL_4,
                LEVEL_5,};

    public static final List<AccessLevel> VALUES = Collections.unmodifiableList(Arrays.asList(VALUES_ARRAY));

    public static AccessLevel get(String literal) {
        for (int i = 0; i < VALUES_ARRAY.length; ++i) {
            AccessLevel result = VALUES_ARRAY[i];
            if (result.toString().equals(literal)) {
                return result;
            }
        }
        return null;
    }

    public static AccessLevel getByName(String name) {
        for (int i = 0; i < VALUES_ARRAY.length; ++i) {
            AccessLevel result = VALUES_ARRAY[i];
            if (result.getName().equals(name)) {
                return result;
            }
        }
        return null;
    }

    public static AccessLevel get(int value) {
        switch (value) {
            case LEVEL_0_VALUE:
                return LEVEL_0;
            case LEVEL_1_VALUE:
                return LEVEL_1;
            case LEVEL_2_VALUE:
                return LEVEL_2;
            case LEVEL_3_VALUE:
                return LEVEL_3;
            case LEVEL_4_VALUE:
                return LEVEL_4;
            case LEVEL_5_VALUE:
                return LEVEL_5;
        }
        return null;
    }

    private final int value;
    private final String name;
    private final String literal;

    private AccessLevel(int value, String name, String literal) {
        this.value = value;
        this.name = name;
        this.literal = literal;
    }

    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    public String getLiteral() {
        return literal;
    }

    @Override
    public String toString() {
        return literal;
    }
}
