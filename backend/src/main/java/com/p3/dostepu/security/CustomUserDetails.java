package com.p3.dostepu.security;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Custom UserDetails implementation: wraps User entity and provides
 * Spring Security authorities based on user roles.
 */
@Getter
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

  private UUID userId;
  private String username;
  private String email;
  private String password;
  private Boolean active;
  private Collection<GrantedAuthority> authorities;

  /**
   * Factory method: create CustomUserDetails from User entity.
   */
  public static CustomUserDetails build(User user) {
    Set<GrantedAuthority> authorities = user.getRoles()
        .stream()
        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
        .collect(Collectors.toSet());

    return new CustomUserDetails(
        user.getId(),
        user.getUsername(),
        user.getEmail(),
        user.getPasswordHash(),
        user.getActive(),
        authorities);
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public Collection<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return active;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return active;
  }

  public boolean hasRole(UserRole role) {
    return authorities.stream()
        .anyMatch(auth -> auth.getAuthority().equals("ROLE_" + role.name()));
  }

  public boolean hasAnyRole(UserRole... roles) {
    for (UserRole role : roles) {
      if (hasRole(role)) {
        return true;
      }
    }
    return false;
  }
}