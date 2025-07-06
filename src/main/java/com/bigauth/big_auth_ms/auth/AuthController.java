package com.bigauth.big_auth_ms.auth;

import com.bigauth.big_auth_ms.auth.dto.UserSessionDto;
import com.bigauth.big_auth_ms.user.User;
import com.bigauth.big_auth_ms.user.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
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
    private final SessionService sessionService;

    /*@PostMapping("/login")
    @Deprecated
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
    } */

    @GetMapping("/google")
    public ResponseEntity<?> googleLogin(@RequestParam String system) {
        // Valida se o sistema é válido
        if (!isValidSystem(system)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Sistema inválido",
                    "message", "O sistema informado não é válido."
            ));
        }

        // Passar o system como parâmetro para o serviço
        String authUrl = googleOAuthService.getGoogleAuthUrl(system);

        return ResponseEntity.ok(Map.of("authUrl", authUrl));
    }



    @GetMapping("/google/callback")
    public void googleCallback(@RequestParam String code,
                               @RequestParam(required = false) String state,
                               HttpServletResponse response) throws IOException {
        try {
            String accessToken = googleOAuthService.exchangeCodeForToken(code);
            User user = googleOAuthService.processGoogleUser(accessToken);

            // Atualizar último login usando o método da interface
            userService.updateLastLogin(user);

            // Criar sessão no Redis
            String sessionId = sessionService.createSession(user, state);

            // Redirecionar para o sistema escolhido com o sessionId
            String redirectUrl = getErrorRedirectUrlBySystem(state);
            response.sendRedirect(redirectUrl + "?sessionId=" + sessionId);

        } catch (Exception e) {
            log.error("Google login failed", e);
            response.sendRedirect("http://localhost:5173/?error=login_failed");
        }
    }

    @PostMapping("/google/token")
    public ResponseEntity<?> googleTokenLogin(@RequestBody Map<String, String> request) {
        try {
            String accessToken = request.get("accessToken");
            String system = request.get("system");

            // Valida se o sistema foi informado
            if (system == null || system.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Sistema obrigatório",
                        "message", "O campo 'system' é obrigatório. Use /auth/systems para ver os sistemas disponíveis."
                ));
            }

            // Valida se o sistema é válido
            if (!isValidSystem(system)) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Sistema inválido",
                        "message", "O sistema informado não é válido. Use /auth/systems para ver os sistemas disponíveis."
                ));
            }

            User user = googleOAuthService.processGoogleUser(accessToken);

            return ResponseEntity.ok(Map.of(
                    "message", "Google login successful",
                    "userId", user.getId(),
                    "email", user.getEmail(),
                    "name", user.getName(),
                    "provider", "GOOGLE",
                    "system", system,
                    "redirectUrl", getRedirectUrlBySystem(system)
            ));

        } catch (Exception e) {
            log.error("Google token login failed", e);
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Login falhou",
                    "message", "Falha no login com Google"
            ));
        }
    }

    @GetMapping("/systems")
    public ResponseEntity<?> systemList() {
        List<Map<String, Object>> systems = List.of(
                Map.of(
                        "id", "expense-control",
                        "name", "Controle de despesas",
                        "description", "Sistema para controle de despesas pessoais"
                ),
                Map.of(
                        "id", "test-system",
                        "name", "Teste",
                        "description", "Sistema de teste"
                )
        );

        return ResponseEntity.ok(Map.of(
                "message", "Lista de sistemas retornada com sucesso",
                "systems", systems
        ));
    }

    @GetMapping("/validate-session/{sessionId}")
    public ResponseEntity<?> validateSession(@PathVariable String sessionId) {
        UserSessionDto sessionData = sessionService.getSession(sessionId);

        if (sessionData == null) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "Sessão inválida",
                    "message", "Sessão não encontrada ou expirada"
            ));
        }

        // Estender sessão se ainda válida
        sessionService.extendSession(sessionId);

        return ResponseEntity.ok(Map.of(
                "message", "Sessão válida",
                "user", Map.of(
                        "id", sessionData.getUserId(),
                        "email", sessionData.getEmail(),
                        "name", sessionData.getName(),
                        "profilePictureUrl", sessionData.getProfilePictureUrl(),
                        "roles", sessionData.getRoles(),
                        "authProvider", sessionData.getAuthProvider(),
                        "system", sessionData.getSystem(),
                        "applications", sessionData.getApplications()
                ),
                "sessionId", sessionId
        ));
    }

    @GetMapping("/check-system-access/{sessionId}/{system}")
    public ResponseEntity<?> checkSystemAccess(@PathVariable String sessionId,
                                               @PathVariable String system) {
        boolean hasAccess = sessionService.hasSystemAccess(sessionId, system);

        if (!hasAccess) {
            return ResponseEntity.status(403).body(Map.of(
                    "error", "Acesso negado",
                    "message", "Usuário não tem acesso ao sistema: " + system
            ));
        }

        return ResponseEntity.ok(Map.of(
                "message", "Acesso autorizado",
                "system", system
        ));
    }

    // Método para validar se o sistema é válido
    private boolean isValidSystem(String system) {
        if (system == null || system.trim().isEmpty()) {
            return false;
        }

        List<String> validSystems = List.of("expense-control", "test-system");
        return validSystems.contains(system.toLowerCase().trim());
    }

    // Método auxiliar para determinar URL de redirecionamento por sistema
    private String getRedirectUrlBySystem(String system) {
        return switch (system.toLowerCase().trim()) {
            case "expense-control" -> "http://localhost:3000/expense-dashboard.html";
            case "test-system" -> "http://localhost:3000/test-dashboard.html";
            default -> "http://localhost:3000/login.html"; // Fallback para erro
        };
    }

    // Método auxiliar para determinar URL de erro por sistema
    private String getErrorRedirectUrlBySystem(String system) {
        return switch (system.toLowerCase().trim()) {
            case "expense-control" -> "http://localhost:3000/expense-login.html";
            case "test-system" -> "http://localhost:3000/test-login.html";
            default -> "http://localhost:3000/login.html";
        };
    }}
