package com.p3.dostepu.config;

import java.util.Set;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.UserRepository;

@Configuration
public class DevUserSeeder {

  @Bean
  CommandLineRunner seedUsers(UserRepository userRepository, PasswordEncoder passwordEncoder) {
    return args -> {
      upsertUser(userRepository, passwordEncoder, "admin", "admin@p3.local", "admin123",
          Set.of(UserRole.ADMIN));
      upsertUser(userRepository, passwordEncoder, "owner1", "owner1@p3.local", "owner123",
          Set.of(UserRole.USER));
      upsertUser(userRepository, passwordEncoder, "owner2", "owner2@p3.local", "owner123",
          Set.of(UserRole.USER));
      upsertUser(userRepository, passwordEncoder, "owner3", "owner3@p3.local", "owner123",
          Set.of(UserRole.USER));
      upsertUser(userRepository, passwordEncoder, "user1", "user1@p3.local", "user123",
          Set.of(UserRole.USER));
      upsertUser(userRepository, passwordEncoder, "user2", "user2@p3.local", "user123",
          Set.of(UserRole.USER));
      upsertUser(userRepository, passwordEncoder, "user3", "user3@p3.local", "user123",
          Set.of(UserRole.USER));
    };
  }

  private void upsertUser(UserRepository userRepository, PasswordEncoder passwordEncoder,
      String username, String email, String plainPassword, Set<UserRole> roles) {
    User user = userRepository.findByUsernameIgnoreCase(username).orElseGet(User::new);
    user.setUsername(username);
    user.setEmail(email);
    user.setActive(true);
    user.setRoles(roles);
    user.setPasswordHash(passwordEncoder.encode(plainPassword));
    userRepository.save(user);
  }
}
