package io.github.seonghun.springjwt.repository;

@Deprecated
public interface JwtBlackRepository {

    void black(String jti, long expiredAt);

    boolean exists(String jti);
}
