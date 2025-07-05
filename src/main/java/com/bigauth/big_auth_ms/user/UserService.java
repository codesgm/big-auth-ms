package com.bigauth.big_auth_ms.user;

import com.bigauth.big_auth_ms.user.enums.AuthProvider;
import com.bigauth.big_auth_ms.user.enums.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface UserService {

    // CRUD básico
    User createUser(User user);
    User findById(Long id);
    User findByEmail(String email);
    User updateUser(User user);
    void deleteUser(Long id);
    Page<User> findAll(Pageable pageable);

    // OAuth2
    User createOrUpdateOAuth2User(OAuth2User oAuth2User, AuthProvider provider);

    // Segurança
    void lockAccount(User user, int minutes);
    void unlockAccount(User user);
    void incrementFailedAttempts(User user);
    void resetFailedAttempts(User user);
    void updateLastLogin(User user);
    boolean isAccountLocked(User user);
}
