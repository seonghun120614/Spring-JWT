package io.github.seonghun.springjwt.service;

import io.github.seonghun.springjwt.util.RedisUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {
    private static final String PREFIX = "blacklist:";

    private final RedisUtil redisUtil;

    public void blacklist(String jti, long remainingMillis) {
        if (remainingMillis <= 0)
            return;
        redisUtil.save(PREFIX, jti, "logout", remainingMillis); // 값은 아무거나 해도 무상관
    }

    public boolean isBlacklisted(String jti) {
        return redisUtil.get(PREFIX, jti) != null;
    }
}
