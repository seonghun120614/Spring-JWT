package io.github.seonghun.springjwt.service;

import io.github.seonghun.springjwt.util.RedisUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RedisUtil redisUtil;

    private static final String PREFIX = "refresh:";
    private static final long TTL_MILLIS = 604800000L;

    @Transactional
    public void save(String userId, String refreshToken) {
        redisUtil.save(
                PREFIX,
                userId,
                refreshToken,
                TTL_MILLIS
        );
    }

    @Transactional(readOnly = true)
    public boolean isValid(String userId, String refreshToken) {
        return redisUtil.isValidAndEquals(PREFIX, userId, refreshToken);
    }

    @Transactional
    public void delete(String userId) {
        redisUtil.delete(PREFIX, userId);
    }
}
