package com.p3.dostepu.security;

import java.util.UUID;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;

/**
 * Custom UserDetailsService: loads user details by username or user ID.
 * Used by authentication manager and JWT filter.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsernameIgnoreCase(username)
        .orElseThrow(() -> new UsernameNotFoundException(
            "User not found with username: " + username));
    return CustomUserDetails.build(user);
  }

  /**
   * Load user details by UUID (used by JWT filter).
   */
  public CustomUserDetails loadUserById(UUID userId) throws UsernameNotFoundException {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new UsernameNotFoundException(
            "User not found with id: " + userId));
    return CustomUserDetails.build(user);
  }
}