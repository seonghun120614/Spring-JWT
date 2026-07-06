package io.github.seonghun.springjwt.controller;

import io.github.seonghun.springjwt.repository.JwtBlackRepository;
import io.github.seonghun.springjwt.service.TokenBlacklistService;
import io.github.seonghun.springjwt.util.CookieHandler;
import io.github.seonghun.springjwt.util.JwtProvider;
import io.github.seonghun.springjwt.util.RedisUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static org.springframework.http.HttpHeaders.SET_COOKIE;

@RestController
@RequiredArgsConstructor
public class SecurityController {
    private final JwtProvider jwtProvider;
    private final CookieHandler cookieHandler;
    private final TokenBlacklistService tokenBlacklistService;

    @GetMapping("/")
    public ResponseEntity<Void> home() {
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/auto")
    public ResponseEntity<?> auto(
            @CookieValue("access_token") String accessToken,
            @CookieValue("refresh_token") String refreshToken
    ) {
        return ResponseEntity.ok(Map.of(
                "access_token", accessToken,
                "refresh_token", refreshToken
        ));
    }

    @PostMapping("/api/logout")
    public ResponseEntity<Void> logout(@CookieValue("refresh_token") String refreshToken,
                                       HttpServletResponse response) {
        if (refreshToken != null) {
            try {
                Claims claims = jwtProvider.parse(refreshToken);
                long remainingMillis = claims.getExpiration().getTime() - System.currentTimeMillis();
                tokenBlacklistService.blacklist(claims.getId(), remainingMillis);
            } catch (JwtException | IllegalArgumentException ignored) { }
        }

        response.addHeader(SET_COOKIE, cookieHandler.createCookie("access_token", "", 0).toString());
        response.addHeader(SET_COOKIE, cookieHandler.createCookie("refresh_token", "", 0).toString());

        return ResponseEntity.noContent().build();
    }
}
