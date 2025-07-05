package com.bigauth.big_auth_ms.user.enums;

import lombok.Getter;

@Getter
public enum AuthProvider {
    LOCAL("Local Authentication"),
    GOOGLE("Google OAuth2");

    private final String description;

    AuthProvider(String description) {
        this.description = description;
    }

}