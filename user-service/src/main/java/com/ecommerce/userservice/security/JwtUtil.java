package com.ecommerce.userservice.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtil {
    private final Key key;
    private final long EXPIRATION_TIME = 86400000; // 24 hours
    private final long BLACKLIST_EXPIRATION = 864000; // 24 hours in seconds

    private final RedisTemplate<String, String> redisTemplate;

    public JwtUtil(@Value("${jwt.secret}") String secretKey, RedisTemplate<String, String> redisTemplate) {
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey));
        this.redisTemplate = redisTemplate;
    }
    // ✅ Generate JWT Token
    public String generateToken(String email, String role) {
        return Jwts.builder()
                .setSubject(email)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // ✅ Get Claims from Token
    public Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ✅ Validate Token
    public boolean validateToken(String token) {
        if (isTokenBlacklisted(token)) return false;
        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException ex) {
            System.out.println("Token Expired: " + ex.getMessage());
        } catch (JwtException ex) {
            System.out.println("Invalid Token: " + ex.getMessage());
        }
        return false;
    }

    // ✅ Invalidate Token (Blacklist it in Redis)
    public void invalidateToken(String token) {
        redisTemplate.opsForValue().set(token, "blacklisted", BLACKLIST_EXPIRATION, TimeUnit.SECONDS);
    }

    // ✅ Check if Token is Blacklisted
    public boolean isTokenBlacklisted(String token) {
        return redisTemplate.hasKey(token);
    }

    // ✅ Extract Email from Token
    public String extractEmail(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    // ✅ Extract Role from Token
    public String extractRole(String token) {
        return getClaimsFromToken(token).get("role", String.class);
    }
}
