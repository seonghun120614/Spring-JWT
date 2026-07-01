package io.github.seonghun.springjwt.repository.impl;

import io.github.seonghun.springjwt.domain.User;
import io.github.seonghun.springjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class UserRepositoryImpl implements UserRepository {
    private final PasswordEncoder passwordEncoder;

    @Override
    public Optional<User> findByUsername(String username) {
        User user = User.builder()
                        .username("hello")
                        .password(passwordEncoder.encode("world"))
                        .roles(Set.of("ROLE_USER"))
                        .build();
        return Optional.of(user);
    }
}
