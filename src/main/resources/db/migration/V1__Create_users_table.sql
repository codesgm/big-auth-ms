-- V1__Create_users_table.sql

-- Create users table
CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       email VARCHAR(255) NOT NULL UNIQUE,
                       name VARCHAR(255) NOT NULL,
                       password_hash VARCHAR(255),
                       google_id VARCHAR(100) UNIQUE,
                       profile_picture_url VARCHAR(500),
                       auth_provider VARCHAR(20) NOT NULL DEFAULT 'LOCAL',
                       is_active BOOLEAN NOT NULL DEFAULT true,
                       is_email_verified BOOLEAN NOT NULL DEFAULT false,
                       email_verification_token VARCHAR(255),
                       password_reset_token VARCHAR(255),
                       password_reset_expires_at TIMESTAMP,
                       last_login_at TIMESTAMP,
                       failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                       account_locked_until TIMESTAMP,
                       created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create user_roles table
CREATE TABLE user_roles (
                            user_id BIGINT NOT NULL,
                            role VARCHAR(50) NOT NULL,
                            PRIMARY KEY (user_id, role),
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create user_applications table
CREATE TABLE user_applications (
                                   user_id BIGINT NOT NULL,
                                   application_code VARCHAR(50) NOT NULL,
                                   PRIMARY KEY (user_id, application_code),
                                   FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_google_id ON users(google_id);
CREATE INDEX idx_user_auth_provider ON users(auth_provider);
CREATE INDEX idx_user_is_active ON users(is_active);
CREATE INDEX idx_user_created_at ON users(created_at);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Insert default admin user (password: admin123)
INSERT INTO users (
    email,
    name,
    password_hash,
    auth_provider,
    is_active,
    is_email_verified
) VALUES (
             'admin@bigauth.com',
             'System Administrator',
             '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', -- bcrypt hash for 'admin123'
             'LOCAL',
             true,
             true
         );

-- Insert admin role for default user
INSERT INTO user_roles (user_id, role)
SELECT id, 'ADMIN' FROM users WHERE email = 'admin@bigauth.com';

INSERT INTO user_roles (user_id, role)
SELECT id, 'USER' FROM users WHERE email = 'admin@bigauth.com';
