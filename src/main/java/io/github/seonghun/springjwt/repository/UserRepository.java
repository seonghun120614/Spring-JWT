package io.github.seonghun.springjwt.repository;

import io.github.seonghun.springjwt.domain.User;
import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface UserRepository {
    Optional<User> findByUsername(String username);
}
