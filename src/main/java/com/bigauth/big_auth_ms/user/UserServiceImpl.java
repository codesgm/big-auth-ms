package com.bigauth.big_auth_ms.user;

import com.bigauth.big_auth_ms.user.enums.AuthProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public User createUser(User user) {
        log.info("Creating new user with email: {}", user.getEmail());

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("User already exists with email: " + user.getEmail());
        }

        return userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
    }

    @Override
    public User updateUser(User user) {
        log.info("Updating user with id: {}", user.getId());
        return userRepository.save(user);
    }

    @Override
    public void deleteUser(Long id) {
        log.info("Deleting user with id: {}", id);
        if (!userRepository.existsById(id)) {
            throw new RuntimeException("User not found with id: " + id);
        }
        userRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> findAll(Pageable pageable) {
        return userRepository.findAll(pageable);
    }

    @Override
    public User createOrUpdateOAuth2User(OAuth2User oAuth2User, AuthProvider provider) {
        String email = oAuth2User.getAttribute("email");
        log.info("Creating or updating OAuth2 user with email: {}", email);

        return userRepository.findByEmail(email)
                .map(existingUser -> updateOAuth2User(existingUser, oAuth2User, provider))
                .orElseGet(() -> createOAuth2User(oAuth2User, provider));
    }

    @Override
    public void lockAccount(User user, int minutes) {
        user.setAccountLockedUntil(LocalDateTime.now().plusMinutes(minutes));
        userRepository.save(user);
        log.warn("Account locked for user: {} until: {}", user.getEmail(), user.getAccountLockedUntil());
    }

    @Override
    public void unlockAccount(User user) {
        user.setAccountLockedUntil(null);
        user.setFailedLoginAttempts(0);
        userRepository.save(user);
        log.info("Account unlocked for user: {}", user.getEmail());
    }

    @Override
    public void incrementFailedAttempts(User user) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        userRepository.save(user);

        log.warn("Failed login attempt #{} for user: {}", user.getFailedLoginAttempts(), user.getEmail());

        // Auto-lock após 5 tentativas
        if (user.getFailedLoginAttempts() >= 5) {
            lockAccount(user, 30); // 30 minutos
        }
    }

    @Override
    public void resetFailedAttempts(User user) {
        if (user.getFailedLoginAttempts() > 0) {
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
            log.info("Reset failed attempts for user: {}", user.getEmail());
        }
    }

    @Override
    public void updateLastLogin(User user) {
        userRepository.updateLastLogin(user.getId(), LocalDateTime.now());
        log.debug("Updated last login for user: {}", user.getEmail());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isAccountLocked(User user) {
        return user.getAccountLockedUntil() != null &&
                user.getAccountLockedUntil().isAfter(LocalDateTime.now());
    }

    // Métodos privados para OAuth2
    private User updateOAuth2User(User existingUser, OAuth2User oAuth2User, AuthProvider provider) {
        existingUser.setName(oAuth2User.getAttribute("name"));
        existingUser.setProfilePictureUrl(oAuth2User.getAttribute("picture"));

        if (provider == AuthProvider.GOOGLE && existingUser.getGoogleId() == null) {
            existingUser.setGoogleId(oAuth2User.getAttribute("sub"));
        }

        // Atualiza provider se necessário
        if (existingUser.getAuthProvider() != provider) {
            existingUser.setAuthProvider(provider);
        }

        return userRepository.save(existingUser);
    }

    private User createOAuth2User(OAuth2User oAuth2User, AuthProvider provider) {
        User newUser = User.builder()
                .email(oAuth2User.getAttribute("email"))
                .name(oAuth2User.getAttribute("name"))
                .profilePictureUrl(oAuth2User.getAttribute("picture"))
                .authProvider(provider)
                .isEmailVerified(true) // OAuth providers já verificam email
                .build();

        if (provider == AuthProvider.GOOGLE) {
            newUser.setGoogleId(oAuth2User.getAttribute("sub"));
        }

        return userRepository.save(newUser);
    }
}
