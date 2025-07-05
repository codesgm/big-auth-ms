package com.bigauth.big_auth_ms.user.dto;

import com.bigauth.big_auth_ms.user.enums.AuthProvider;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Set;

@Data
public class UserRequest {

    @Email(message = "Email must be valid")
    private String email;

    @Size(min = 2, max = 255, message = "Name must be between 2 and 255 characters")
    private String name;

    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;

    private String profilePictureUrl;
    private AuthProvider authProvider;
    private Set<String> applications;
    private Boolean isActive;

    // Validação condicional para criação
    @NotBlank(message = "Email is required", groups = CreateValidation.class)
    public String getEmail() { return email; }

    @NotBlank(message = "Name is required", groups = CreateValidation.class)
    public String getName() { return name; }

    public interface CreateValidation {}
}
