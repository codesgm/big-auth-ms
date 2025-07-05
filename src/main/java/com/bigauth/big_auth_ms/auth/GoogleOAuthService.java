package com.bigauth.big_auth_ms.auth;

import com.bigauth.big_auth_ms.user.User;
import com.bigauth.big_auth_ms.user.UserService;
import com.bigauth.big_auth_ms.user.enums.AuthProvider;
import com.bigauth.big_auth_ms.user.enums.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoogleOAuthService {

    private final UserService userService;
    private final WebClient.Builder webClientBuilder;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Value("${google.oauth2.user-info-url}")
    private String userInfoUrl;

    public User processGoogleUser(String accessToken) {
        // Buscar dados do usuário no Google
        Map<String, Object> userInfo = getUserInfoFromGoogle(accessToken);

        String email = (String) userInfo.get("email");
        String name = (String) userInfo.get("name");
        String googleId = (String) userInfo.get("id");
        String pictureUrl = (String) userInfo.get("picture");

        log.info("Processing Google user: {}", email);

        // Verificar se usuário já existe
        User user;
        try {
            user = userService.findByEmail(email);
            // Atualizar dados do Google se necessário
            updateGoogleUserData(user, googleId, name, pictureUrl);
        } catch (Exception e) {
            // Criar novo usuário
            user = createGoogleUser(email, name, googleId, pictureUrl);
        }

        return userService.updateUser(user);
    }

    private Map<String, Object> getUserInfoFromGoogle(String accessToken) {
        WebClient webClient = webClientBuilder.build();

        return webClient.get()
                .uri(userInfoUrl)
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(Map.class)
                .block();
    }

    private User createGoogleUser(String email, String name, String googleId, String pictureUrl) {
        return User.builder()
                .email(email)
                .name(name)
                .googleId(googleId)
                .profilePictureUrl(pictureUrl)
                .authProvider(AuthProvider.GOOGLE)
                .isActive(true)
                .isEmailVerified(true) // Google já verificou
                .roles(Set.of(Role.USER))
                .build();
    }

    private void updateGoogleUserData(User user, String googleId, String name, String pictureUrl) {
        if (user.getGoogleId() == null) {
            user.setGoogleId(googleId);
        }
        user.setName(name);
        user.setProfilePictureUrl(pictureUrl);
        user.setAuthProvider(AuthProvider.GOOGLE);
    }

    public String getGoogleAuthUrl() {
        return "https://accounts.google.com/o/oauth2/v2/auth?" +
                "client_id=" + clientId +
                "&redirect_uri=http://localhost:8080/api/auth/google/callback" +
                "&scope=email profile" +
                "&response_type=code" +
                "&access_type=offline";
    }

    public String exchangeCodeForToken(String code) {
        WebClient webClient = webClientBuilder.build();

        Map tokenResponse = webClient.post()
                .uri("https://oauth2.googleapis.com/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue("client_id=" + clientId +
                        "&client_secret=" + clientSecret +
                        "&code=" + code +
                        "&grant_type=authorization_code" +
                        "&redirect_uri=http://localhost:8080/api/auth/google/callback")
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        return (String) tokenResponse.get("access_token");
    }
}
