package io.github.seonghun.springjwt.repository.impl;

import io.github.seonghun.springjwt.repository.JwtBlackRepository;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class JwtBlackRepositoryImpl implements JwtBlackRepository {
    private final ConcurrentMap<String, Long> store = new ConcurrentHashMap<>();

    @Override
    public void black(String jti, long expiredAt) {
        store.put(jti, expiredAt);
    }

    @Override
    public boolean exists(String jti) {
        Long expiredAt = store.get(jti);
        if (expiredAt == null) return false;
        if (expiredAt < System.currentTimeMillis()) {
            store.remove(jti);
            return false;
        }
        return true;
    }
}
