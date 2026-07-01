package io.github.seonghun.springjwt.security.userpass;

import io.github.seonghun.springjwt.domain.CustomUserDetails;
import io.github.seonghun.springjwt.util.CookieHandler;
import io.github.seonghun.springjwt.util.JwtProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Collection;
import java.util.Objects;

@RequiredArgsConstructor
public class UsernamePasswordAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final CookieHandler cookieHandler;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication
    ) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String name = Objects.requireNonNull(userDetails).getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

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
    }
}
