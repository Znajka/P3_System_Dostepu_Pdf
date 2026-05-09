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
      // Docker/local demo: 1 admin + 4 users (password = username + "123")
      upsertUser(userRepository, passwordEncoder, "admin", "admin@p3.local", "admin123",
          Set.of(UserRole.ADMIN));
      upsertUser(userRepository, passwordEncoder, "alice", "alice@p3.local", "alice123",
          Set.of(UserRole.USER));
      upsertUser(userRepository, passwordEncoder, "bob", "bob@p3.local", "bob123",
          Set.of(UserRole.USER));
      upsertUser(userRepository, passwordEncoder, "carol", "carol@p3.local", "carol123",
          Set.of(UserRole.USER));
      upsertUser(userRepository, passwordEncoder, "dave", "dave@p3.local", "dave123",
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
