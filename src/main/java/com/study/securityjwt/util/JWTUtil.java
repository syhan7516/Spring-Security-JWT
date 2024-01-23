package com.study.securityjwt.util;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    // 키를 저장할 객체
    private SecretKey secretKey;

    // properties 변수에서 값을 가져오기
    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {

        // 객체 타입으로 암호화하여 생성
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 검증 - 아이디 추출 메서드
    public String getUsername(String token) {

        // Jwts.parser() : JWT 파싱
        // verifyWith(secretKey) : 해당 서버에서 생성되었는지 검증
        // parseSignedClaims(token).getPayload().get("claims key", String.class)
        // -> 토큰을 파싱해 페이로드의 클레임 키에 해당하는 값을 문자열로 가져오기
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    // 검증 - Role 추출 메서드
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    // 검증 - 만료 기간 추출 메서드
    public Boolean isExpired(String token) {

        // getExpiration().before(new Date())
        // -> 만료 기간이 현재 시간 이전인지 확인
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    // 토큰 생성 메서드
    public String createJwt(String username, String role, Long expiredMs) {

        return Jwts.builder()
                // 클레임 1
                .claim("username", username)
                // 클레임 2
                .claim("role", role)
                // 발행 시점
                .issuedAt(new Date(System.currentTimeMillis()))
                // 만료 시점
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                // 서명
                .signWith(secretKey)
                // 압축
                .compact();
    }
}