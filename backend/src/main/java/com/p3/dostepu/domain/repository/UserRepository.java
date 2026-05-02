package com.p3.dostepu.domain.repository;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.p3.dostepu.domain.entity.User;

/**
 * Spring Data JPA repository for User entity.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
  Optional<User> findByUsernameIgnoreCase(String username);

  Optional<User> findByEmail(String email);

  Optional<User> findByIdAndActiveTrue(UUID id);
}	