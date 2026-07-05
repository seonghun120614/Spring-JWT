# Spring JWT

Spring Security 필터 체인을 직접 구성하여 쿠키 기반 JWT 인증을 구현한 학습 프로젝트입니다.
세션 없이(Stateless) Access / Refresh 토큰으로 인증을 처리하며, Refresh Token Rotation과 블랙리스트를 통해 토큰 탈취에 대응합니다.

## 기술 스택

- Java / Spring Boot
- Spring Security (커스텀 필터 체인)
- JJWT
- Lombok

## 인증 흐름

```
[로그인]
POST /api/login (username, password)
  → CustomUsernamePasswordFilter → DaoAuthenticationProvider 검증
  → 성공 시 access_token / refresh_token을 HttpOnly 쿠키로 발급 (Set-Cookie)

[인증 요청]
GET /** (access_token 쿠키)
  → JwtAuthenticationFilter가 토큰 검증 후 SecurityContext에 인증 세팅

[토큰 재발급]  ※ 프론트 재시도 방식
access 만료 → 서버가 401 응답
  → 프론트가 POST /api/refresh 호출 (refresh_token 쿠키)
  → JwtRefreshFilter: 블랙리스트 검사 → 사용된 refresh를 블랙리스트 등록(Rotation)
    → 새 access / refresh 발급 (200)
  → 프론트가 원래 요청을 재시도

[로그아웃]
POST /logout
  → refresh_token을 블랙리스트에 등록하고 쿠키 제거 (멱등 처리)
```

## 주요 컴포넌트

| 컴포넌트 | 역할 |
|---|---|
| `CustomUsernamePasswordFilter` | `POST /api/login`에서 JSON/Form 로그인 처리 |
| `UsernamePasswordAuthenticationSuccessHandler` | 인증 성공 시 JWT 발급 및 쿠키 세팅 |
| `JwtAuthenticationFilter` | 요청 쿠키의 access_token 검증 → SecurityContext 인증 세팅 |
| `JwtRefreshFilter` | `/api/refresh` 전용. 블랙리스트 검사 + Rotation + 재발급 |
| `JwtBlackRepository` | jti 기반 인메모리 블랙리스트 (`ConcurrentHashMap`, lazy eviction) |
| `JwtProvider` | 토큰 생성/파싱. roles는 문자열 리스트로 저장, refresh에 jti 부여 |
| `CookieHandler` | HttpOnly / Secure 쿠키 생성 및 파싱 |

## API

| Method | Path | 인증 | 설명 |
|---|---|---|---|
| POST | `/api/login` | X | 로그인, 토큰 쿠키 발급 |
| POST | `/api/refresh` | X (refresh 쿠키) | 토큰 재발급 (Rotation) |
| POST | `/` | O | 로그아웃 (블랙리스트 등록 + 쿠키 제거) |
| GET | `/` | O | 인증 확인용 |
| GET | `/auto` | O | 쿠키 값 확인용 (테스트) |

## 보안 설계 포인트

- **HttpOnly 쿠키**: JS에서 토큰 접근 불가 → XSS 탈취 방어
- **Refresh Token Rotation**: 재발급 시 사용된 refresh를 즉시 블랙리스트 등록 → refresh는 1회용
- **jti 블랙리스트**: refresh 토큰에만 jti(UUID)를 부여, 로그아웃/재사용 시 만료 시각까지 무효 처리
- **roles 직렬화**: JWT에는 `GrantedAuthority` 객체가 아닌 문자열 리스트(`["ROLE_USER"]`)로 저장

## 실행

```bash
./gradlew bootRun
```

테스트 계정: `hello` / `world` (인메모리 저장소)

## 테스트 시나리오

1. 로그인 → 인증 필요 엔드포인트 접근 확인
2. `/api/refresh` 호출 → 새 토큰 발급 확인
3. 사용된(옛) refresh로 재호출 → 401 (Rotation 검증)
4. 로그아웃 후 refresh 호출 → 401 (블랙리스트 검증)