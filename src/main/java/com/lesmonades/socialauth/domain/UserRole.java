package com.lesmonades.socialauth.domain;

import java.util.Arrays;

public enum UserRole {
    ROLE_ADMIN, ROLE_CLIENT, ROLE_USER;

    public static boolean isInEnum(String value) {
        return Arrays.stream(UserRole.values()).anyMatch(e -> e.name().equals(value));
    }
}
