package io.github.seonghun.springjwt.security.jwt;

import io.github.seonghun.springjwt.util.CookieHandler;
import io.github.seonghun.springjwt.util.JwtProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final CookieHandler cookieHandler;
    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain
    ) throws ServletException, IOException {
        // Parsing
        Map<String, String> tokens = cookieHandler.getMap(request.getCookies());

        if (!tokens.containsKey("access_token")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String accessToken = tokens.get("access_token");
            Claims accessClaim = jwtProvider.parse(accessToken);

            String username = accessClaim.getSubject();
            List<String> roles = accessClaim.get("roles", List.class);
            List<GrantedAuthority> authorities = roles.stream()
                                                      .map(SimpleGrantedAuthority::new)
                                                      .collect(Collectors.toList());
            var jwtAuth = new JwtAuthentication(username, authorities);

            SecurityContextHolder.getContext().setAuthentication(jwtAuth);
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            filterChain.doFilter(request, response);
        } catch (JwtException | IllegalArgumentException e) {
            response.sendError(401, "인증 형식 오류");
        }
    }
}
