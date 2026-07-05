package io.github.seonghun.springjwt.security.userpwd;

import io.github.seonghun.springjwt.domain.CustomUserDetails;
import io.github.seonghun.springjwt.domain.User;
import io.github.seonghun.springjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                                  .orElseThrow(() -> new UsernameNotFoundException("The user could not be found or the user has no GrantedAuthority"));

        Set<GrantedAuthority> authorities = user.getRoles().stream()
                                                .map(SimpleGrantedAuthority::new)        // String → GrantedAuthority
                                                .collect(Collectors.toSet());

        return new CustomUserDetails(user.getUsername(),
                                     user.getPassword(),
                                     authorities);
    }
}
