package com.bigauth.big_auth_ms.user;

import com.bigauth.big_auth_ms.user.dto.UserRequest;
import com.bigauth.big_auth_ms.user.dto.UserResponse;
import com.bigauth.big_auth_ms.user.enums.Role;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping
    public ResponseEntity<UserResponse> createUser(
            @Validated(UserRequest.CreateValidation.class) @RequestBody UserRequest request) {

        log.info("Creating user with email: {}", request.getEmail());

        User user = User.builder()
                .email(request.getEmail())
                .name(request.getName())
                .profilePictureUrl(request.getProfilePictureUrl())
                .authProvider(request.getAuthProvider())
                .applications(request.getApplications())
                .build();

        if (request.getPassword() != null) {
            user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        }

        User savedUser = userService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(savedUser));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or authentication.name == @userService.findById(#id).email")
    public ResponseEntity<UserResponse> getUser(@PathVariable Long id) {
        User user = userService.findById(id);
        return ResponseEntity.ok(toResponse(user));
    }

    @GetMapping("/email/{email}")
    @PreAuthorize("hasRole('ADMIN') or authentication.name == #email")
    public ResponseEntity<UserResponse> getUserByEmail(@PathVariable String email) {
        User user = userService.findByEmail(email);
        return ResponseEntity.ok(toResponse(user));
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> getUsers(Pageable pageable) {
        Page<User> users = userService.findAll(pageable);
        return ResponseEntity.ok(users.map(this::toResponse));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or authentication.name == @userService.findById(#id).email")
    public ResponseEntity<UserResponse> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UserRequest request) {

        User user = userService.findById(id);
        updateUserFromRequest(user, request);

        User updatedUser = userService.updateUser(user);
        return ResponseEntity.ok(toResponse(updatedUser));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    // Endpoints de gerenciamento simplificados
    @PostMapping("/{id}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> manageRoles(
            @PathVariable Long id,
            @RequestBody Set<Role> roles) {
        User user = userService.findById(id);
        user.setRoles(roles);
        userService.updateUser(user);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/applications")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> manageApplications(
            @PathVariable Long id,
            @RequestBody Set<String> applications) {
        User user = userService.findById(id);
        user.setApplications(applications);
        userService.updateUser(user);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/unlock")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> unlockAccount(@PathVariable Long id) {
        User user = userService.findById(id);
        userService.unlockAccount(user);
        return ResponseEntity.ok().build();
    }

    // Endpoint para outros microserviços validarem usuário
    @GetMapping("/{id}/validate")
    public ResponseEntity<UserResponse> validateUser(@PathVariable Long id) {
        User user = userService.findById(id);
        UserResponse response = toResponse(user);
        response.setIsAccountLocked(userService.isAccountLocked(user));
        return ResponseEntity.ok(response);
    }

    // Método helper para converter User -> UserResponse
    private UserResponse toResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .profilePictureUrl(user.getProfilePictureUrl())
                .authProvider(user.getAuthProvider())
                .isActive(user.getIsActive())
                .isEmailVerified(user.getIsEmailVerified())
                .roles(user.getRoles())
                .applications(user.getApplications())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .build();
    }

    // Método helper para atualizar User com UserRequest
    private void updateUserFromRequest(User user, UserRequest request) {
        if (request.getName() != null) user.setName(request.getName());
        if (request.getProfilePictureUrl() != null) user.setProfilePictureUrl(request.getProfilePictureUrl());
        if (request.getIsActive() != null) user.setIsActive(request.getIsActive());
        if (request.getApplications() != null) user.setApplications(request.getApplications());
        if (request.getPassword() != null) {
            user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        }
    }
}
