package io.github.seonghun.springjwt.util;

import io.github.seonghun.springjwt.config.properties.CookieProperty;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CookieHandler {
    private final CookieProperty cookieProperty;

    public ResponseCookie createCookie(String name, String value, long maxAge) {
        return ResponseCookie.from(name, value)
                             .httpOnly(cookieProperty.httpOnly())
                             .secure(cookieProperty.secure())
                             .sameSite(cookieProperty.sameSite())
                             .path(cookieProperty.path())
                             .maxAge(maxAge)
                             .build();
    }
}
