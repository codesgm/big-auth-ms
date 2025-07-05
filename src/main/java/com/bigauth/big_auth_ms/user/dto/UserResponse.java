package com.bigauth.big_auth_ms.user.dto;

import com.bigauth.big_auth_ms.user.enums.AuthProvider;
import com.bigauth.big_auth_ms.user.enums.Role;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL) // Só inclui campos não nulos
public class UserResponse {
    private Long id;
    private String email;
    private String name;
    private String profilePictureUrl;
    private AuthProvider authProvider;
    private Boolean isActive;
    private Boolean isEmailVerified;
    private Set<Role> roles;
    private Set<String> applications;
    private LocalDateTime lastLoginAt;
    private LocalDateTime createdAt;

    // Para validação de outros microserviços
    private Boolean isAccountLocked;
}
