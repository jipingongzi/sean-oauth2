package org.example.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Component
public class JwtUtils {
    private String jwtSigningKey = "secret";

    /**
     * 从JWT中提取用户名
     */
    public String extractUsername(String token){
        return extractClaim(token,Claims::getSubject);
    }

    /**
     * 从JWT中提取过期时间
     */
    public Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }

    /**
     * 检查JWT是否包含指定的声明
     */
    public boolean hasClaim(String token,String claimName){
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) !=null;
    }

    /**
     * 从JWT中提取指定声明
     */
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 从JWT中提取所有声明
     */
    public Claims extractAllClaims(String token){
        try {
            return Jwts.parser().setSigningKey(jwtSigningKey).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            e.printStackTrace();
            // return a default Claims object or null
        }
        return null;
    }

    /**
     * 检查JWT是否已过期
     */
    public Boolean isTokenExpired(String token){
        Date expirationDate = extractExpiration(token);
        if (expirationDate == null) {
            return true; // or false based on your requirements
        }
        return expirationDate.before(new Date());
    }

    /**
     * 生成JWT
     */
    public String generateToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        return createToken(claims,userDetails);
    }

    /**
     * 生成带有指定声明的JWT
     */
    public String generateToken(UserDetails userDetails,Map<String,Object>claims){
        return createToken(claims,userDetails);
    }

    /**
     * 创建JWT
     */
    public String createToken(Map<String, Object> claims, UserDetails userDetails){
        return Jwts.builder().setClaims(claims)
                .setSubject(userDetails.getUsername())
                .claim("authorities",userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24)))
                .signWith(SignatureAlgorithm.HS256,jwtSigningKey).compact();
    }

    /**
     * 验证JWT是否有效
     */
    public Boolean isTokenValid(String token,UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
