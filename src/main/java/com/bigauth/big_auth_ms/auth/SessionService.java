package com.bigauth.big_auth_ms.auth;

import com.bigauth.big_auth_ms.auth.dto.UserSessionDto;
import com.bigauth.big_auth_ms.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    private static final String SESSION_PREFIX = "user_session:";
    private static final long SESSION_TIMEOUT_MINUTES = 30;

    @Transactional(readOnly = true)
    public String createSession(User user, String system) {
        try {
            // Gerar ID único para a sessão
            String sessionId = UUID.randomUUID().toString();

            // Criar DTO com dados da sessão
            UserSessionDto sessionData = new UserSessionDto(
                    user.getId(),
                    user.getEmail(),
                    user.getName(),
                    user.getProfilePictureUrl(),
                    user.getAuthProvider(),
                    user.getRoles(),
                    user.getApplications(),
                    system,
                    LocalDateTime.now(),
                    LocalDateTime.now().plusMinutes(SESSION_TIMEOUT_MINUTES),
                    user.getLastLoginAt()
            );

            // Converter para JSON
         // String sessionJson = objectMapper.writeValueAsString(sessionData);

            // Salvar no Redis com expiração
            String redisKey = SESSION_PREFIX + sessionId;
            redisTemplate.opsForValue().set(redisKey, "testetestetestes", SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);

            log.info("Sessão criada: {} para usuário: {} no sistema: {}", sessionId, user.getEmail(), system);
            return sessionId;

        } catch (Exception e) {
            log.error("Erro ao criar sessão para usuário: {}", user.getEmail(), e);
            throw new RuntimeException("Erro ao criar sessão", e);
        }
    }

    public UserSessionDto getSession(String sessionId) {
        try {
            String redisKey = SESSION_PREFIX + sessionId;
            String sessionJson = redisTemplate.opsForValue().get(redisKey);

            if (sessionJson == null) {
                log.warn("Sessão não encontrada: {}", sessionId);
                return null;
            }

            UserSessionDto sessionData = objectMapper.readValue(sessionJson, UserSessionDto.class);

            // Verificar se a sessão não expirou
            if (sessionData.getExpiresAt().isBefore(LocalDateTime.now())) {
                log.warn("Sessão expirada: {}", sessionId);
                invalidateSession(sessionId);
                return null;
            }

            return sessionData;

        } catch (Exception e) {
            log.error("Erro ao recuperar sessão: {}", sessionId, e);
            return null;
        }
    }

    public boolean isSessionValid(String sessionId) {
        UserSessionDto session = getSession(sessionId);
        return session != null;
    }

    public void invalidateSession(String sessionId) {
        String redisKey = SESSION_PREFIX + sessionId;
        redisTemplate.delete(redisKey);
        log.info("Sessão invalidada: {}", sessionId);
    }

    public void extendSession(String sessionId) {
        try {
            UserSessionDto sessionData = getSession(sessionId);
            if (sessionData != null) {
                // Atualizar tempo de expiração
                sessionData.setExpiresAt(LocalDateTime.now().plusMinutes(SESSION_TIMEOUT_MINUTES));

                String sessionJson = objectMapper.writeValueAsString(sessionData);
                String redisKey = SESSION_PREFIX + sessionId;

                redisTemplate.opsForValue().set(redisKey, sessionJson, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                log.debug("Sessão estendida: {}", sessionId);
            }
        } catch (Exception e) {
            log.error("Erro ao estender sessão: {}", sessionId, e);
        }
    }

    public boolean hasSystemAccess(String sessionId, String system) {
        UserSessionDto sessionData = getSession(sessionId);
        if (sessionData == null) {
            return false;
        }

        // Verificar se o usuário tem acesso ao sistema
        return sessionData.getApplications().contains(system) ||
                sessionData.getSystem().equals(system);
    }

    public void addSystemAccess(String sessionId, String system) {
        try {
            UserSessionDto sessionData = getSession(sessionId);
            if (sessionData != null) {
                sessionData.getApplications().add(system);

                String sessionJson = objectMapper.writeValueAsString(sessionData);
                String redisKey = SESSION_PREFIX + sessionId;

                redisTemplate.opsForValue().set(redisKey, sessionJson, SESSION_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                log.info("Sistema {} adicionado à sessão: {}", system, sessionId);
            }
        } catch (Exception e) {
            log.error("Erro ao adicionar sistema à sessão: {}", sessionId, e);
        }
    }
}
