package com.example.gateway.config;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;


    private static final String CLAIM_ROLES = "roles";

    private SecretKey getSigningKey() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            keyBytes = Arrays.copyOf(keyBytes, 32);
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }


    public String extractUsername(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    public List<GrantedAuthority> extractRoles(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            Object rolesObj = claims.get(CLAIM_ROLES);
            if (rolesObj instanceof List<?> roleList) {
                return roleList.stream()
                        .filter(r -> r instanceof String)
                        .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                        .collect(Collectors.toList());
            }
        } catch (Exception e) {
            log.debug("Failed to extract roles from token: {}", e.getMessage());
        }
        return Collections.emptyList();
    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            String username = extractUsername(token);
            return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    public boolean validateToken(String token) {
        try {
            getClaimsFromToken(token);
            return !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Invalid JWT: {}", e.getMessage());
            return false;
        }
    }

    public Date extractExpiry(String token) {
        try {
            return getClaimsFromToken(token).getExpiration();
        } catch (Exception e) {
            return null;
        }
    }

    public boolean isExpiryValid(String token) {
        return !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        try {
            Date expiration = getClaimsFromToken(token).getExpiration();
            return expiration == null || expiration.before(new Date());
        } catch (Exception e) {
            return true;
        }
    }
}
