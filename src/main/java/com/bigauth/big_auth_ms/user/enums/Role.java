package com.bigauth.big_auth_ms.user.enums;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Getter
public enum Role {
    USER("Standard User"),
    ADMIN("Administrator"),
    MODERATOR("Moderator");

    private final String description;

    Role(String description) {
        this.description = description;
    }

    public GrantedAuthority toAuthority() {
        return new SimpleGrantedAuthority("ROLE_" + this.name());
    }
}
