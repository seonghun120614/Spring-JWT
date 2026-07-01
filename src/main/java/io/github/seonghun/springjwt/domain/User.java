package io.github.seonghun.springjwt.domain;

import lombok.Builder;
import lombok.Getter;

import java.util.Set;

@Builder
@Getter
public class User {
    private String username;
    private String password;
    private Set<String> roles;
}
