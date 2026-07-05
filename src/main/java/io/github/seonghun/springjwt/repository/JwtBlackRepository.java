package io.github.seonghun.springjwt.repository;

public interface JwtBlackRepository {

    void black(String jti, long expiredAt);

    boolean exists(String jti);
}
