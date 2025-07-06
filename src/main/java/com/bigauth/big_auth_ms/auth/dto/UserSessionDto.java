package com.bigauth.big_auth_ms.auth.dto;

import com.bigauth.big_auth_ms.user.enums.AuthProvider;
import com.bigauth.big_auth_ms.user.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSessionDto implements Serializable {
    private Long userId;
    private String email;
    private String name;
    private String profilePictureUrl;
    private AuthProvider authProvider;
    private Set<Role> roles;
    private Set<String> applications;
    private String system; // Sistema atual que o usuário está acessando
    private LocalDateTime loginTime;
    private LocalDateTime expiresAt;
    private LocalDateTime lastLoginAt;
}
