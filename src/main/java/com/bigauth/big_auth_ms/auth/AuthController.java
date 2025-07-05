package com.bigauth.big_auth_ms.auth;

import com.bigauth.big_auth_ms.user.User;
import com.bigauth.big_auth_ms.user.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final GoogleOAuthService googleOAuthService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            String password = request.get("password");

            User user = userService.findByEmail(email);

            if (passwordEncoder.matches(password, user.getPasswordHash())) {
                return ResponseEntity.ok(Map.of(
                        "userId", user.getId(),
                        "email", user.getEmail(),
                        "roles", user.getRoles()
                ));
            }

            return ResponseEntity.badRequest().body("Invalid credentials");

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid credentials");
        }
    }


    @GetMapping("/google")
    public ResponseEntity<?> googleLogin() {
        String authUrl = googleOAuthService.getGoogleAuthUrl();
        return ResponseEntity.ok(Map.of("authUrl", authUrl));
    }

    @GetMapping("/google/callback")
    public void googleCallback(@RequestParam String code, HttpServletResponse response) throws IOException {
        try {
            // Trocar código por token de acesso
            String accessToken = googleOAuthService.exchangeCodeForToken(code);

            // Processar usuário do Google
            User user = googleOAuthService.processGoogleUser(accessToken);

            // Criar dados do usuário para enviar
            ObjectMapper mapper = new ObjectMapper();
            String userData = Base64.getEncoder().encodeToString(
                    mapper.writeValueAsString(Map.of(
                            "userId", user.getId(),
                            "email", user.getEmail(),
                            "name", user.getName(),
                            "provider", "GOOGLE",
                            "profilePictureUrl", user.getProfilePictureUrl() != null ? user.getProfilePictureUrl() : "",
                            "roles", user.getRoles()
                    )).getBytes()
            );

            // Redirecionar para o dashboard com dados
            response.sendRedirect("http://localhost:3000/dashboard.html?data=" + userData);

        } catch (Exception e) {
            log.error("Google login failed", e);
            response.sendRedirect("http://localhost:3000/login.html?error=google_login_failed");
        }
    }


    @PostMapping("/google/token")
    public ResponseEntity<?> googleTokenLogin(@RequestBody Map<String, String> request) {
        try {
            String accessToken = request.get("accessToken");

            User user = googleOAuthService.processGoogleUser(accessToken);

            return ResponseEntity.ok(Map.of(
                    "message", "Google login successful",
                    "userId", user.getId(),
                    "email", user.getEmail(),
                    "name", user.getName(),
                    "provider", "GOOGLE"
            ));

        } catch (Exception e) {
            log.error("Google token login failed", e);
            return ResponseEntity.badRequest().body("Google login failed");
        }
    }
}
