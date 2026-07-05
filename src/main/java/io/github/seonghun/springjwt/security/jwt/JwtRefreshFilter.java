package io.github.seonghun.springjwt.security.jwt;

import io.github.seonghun.springjwt.repository.JwtBlackRepository;
import io.github.seonghun.springjwt.util.CookieHandler;
import io.github.seonghun.springjwt.util.JwtProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class JwtRefreshFilter extends OncePerRequestFilter {
    private final static String INCLUDE_PATHS = "/api/refresh";

    private final JwtBlackRepository jwtBlackRepository;
    private final CookieHandler cookieHandler;
    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain
    ) throws IOException {
        // Parsing
        Map<String, String> tokens = cookieHandler.getMap(request.getCookies());

        try {
            String oldRefreshToken = tokens.getOrDefault("refresh_token", "");
            Claims oldRefreshClaim = jwtProvider.parse(oldRefreshToken);

            if (jwtBlackRepository.exists(oldRefreshClaim.getId())) {
                response.sendError(401, "무효화된 토큰");
                return;
            }

            String jti = oldRefreshClaim.getId();
            String name = oldRefreshClaim.getSubject();
            Set<String> authorities = oldRefreshClaim.get("roles", Set.class);

            // 만들기 전 jti black
            jwtBlackRepository.black(jti, oldRefreshClaim.getExpiration().getTime());

            String accessToken = jwtProvider.createAccessToken(name, authorities);
            String refreshToken = jwtProvider.createRefreshToken(name, authorities);

            var accessCookie = cookieHandler.createCookie("access_token",
                                                          accessToken,
                                                          jwtProvider.getAccessExpirySeconds());
            var refreshCookie = cookieHandler.createCookie("refresh_token",
                                                           refreshToken,
                                                           jwtProvider.getRefreshExpirySeconds());

            response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        } catch (JwtException | IllegalArgumentException e) {
            response.sendError(401, "인증 형식 오류");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !INCLUDE_PATHS.equals(request.getRequestURI());
    }
}
