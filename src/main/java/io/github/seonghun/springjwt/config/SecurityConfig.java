package io.github.seonghun.springjwt.config;

import io.github.seonghun.springjwt.config.properties.CookieProperty;
import io.github.seonghun.springjwt.config.properties.JwtProperty;
import io.github.seonghun.springjwt.security.userpass.CustomUsernamePasswordFilter;
import io.github.seonghun.springjwt.security.userpass.CustomUserDetailsService;
import io.github.seonghun.springjwt.security.userpass.UsernamePasswordAuthenticationFailureHandler;
import io.github.seonghun.springjwt.security.userpass.UsernamePasswordAuthenticationManager;
import io.github.seonghun.springjwt.security.userpass.UsernamePasswordAuthenticationSuccessHandler;
import io.github.seonghun.springjwt.util.CookieHandler;
import io.github.seonghun.springjwt.util.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tools.jackson.databind.ObjectMapper;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties({
        CookieProperty.class,
        JwtProperty.class
})
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   CustomUsernamePasswordFilter usernamePasswordFilter) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/login").permitAll()
                        .anyRequest().authenticated()
                )
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilterAt(usernamePasswordFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }

    @Bean
    public CustomUsernamePasswordFilter usernamePasswordFilter(
            CookieHandler cookieHandler,
            JwtProvider jwtProvider,
            ObjectMapper objectMapper,
            DaoAuthenticationProvider daoAuthenticationProvider
    ) {
        final var usernamePasswordAuthenticationManager
                = new UsernamePasswordAuthenticationManager(daoAuthenticationProvider);
        var usernamePasswordFilter = new CustomUsernamePasswordFilter(usernamePasswordAuthenticationManager,
                                                                      objectMapper);

        var usernamePasswordAuthenticationSuccessHandler
                = new UsernamePasswordAuthenticationSuccessHandler(jwtProvider, cookieHandler);
        var usernamePasswordAuthenticationFailureHandler
                = new UsernamePasswordAuthenticationFailureHandler(objectMapper);

        usernamePasswordFilter.setAuthenticationSuccessHandler(usernamePasswordAuthenticationSuccessHandler);
        usernamePasswordFilter.setAuthenticationFailureHandler(usernamePasswordAuthenticationFailureHandler);
        return usernamePasswordFilter;
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(
            PasswordEncoder passwordEncoder,
            CustomUserDetailsService userDetailsService
    ) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
