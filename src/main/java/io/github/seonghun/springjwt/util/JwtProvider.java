package io.github.seonghun.springjwt.util;

import io.github.seonghun.springjwt.config.properties.JwtProperty;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtProvider {
    private final JwtProperty jwtProperty;
    private SecretKey key;

    @PostConstruct
    void init() {
        this.key = Keys.hmacShaKeyFor(
                jwtProperty.secret().getBytes()
        );
    }

    public String createAccessToken(String username,
                                    Collection<? extends GrantedAuthority> authorities) {
        return createToken(username, authorities, jwtProperty.accessExpireMilliSeconds());
    }

    public String createRefreshToken(String username,
                                     Collection<? extends GrantedAuthority> authorities) {
        return createToken(username, authorities, jwtProperty.refreshExpireMilliSeconds());
    }

    private String createToken(String username,
                              Collection<? extends GrantedAuthority> authorities,
                              long expireMilliSeconds) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expireMilliSeconds);

        String roles = authorities.stream()
                                  .map(GrantedAuthority::getAuthority)
                                  .collect(Collectors.joining(","));

        return Jwts.builder()
                   .subject(username)
                   .claim("roles", roles)
                   .issuedAt(now)
                   .expiration(expiry)
                   .signWith(key)
                   .compact();
    }

    public long getAccessExpirySeconds() {
        return jwtProperty.accessExpireMilliSeconds();
    }

    public long getRefreshExpirySeconds() {
        return jwtProperty.refreshExpireMilliSeconds();
    }
}
