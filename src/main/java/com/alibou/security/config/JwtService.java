package com.alibou.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    public String extractUsername(String token) {
        //the Subject of the token should be email or userName
        return extractClaim(token, Claims::getSubject);
    }

    // extract one single claim    //that mean extract  specific  attribute  from the body of claims
    // Function<Claims ,T>  Claims: Type of function   T: the type that i want to return
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extracAlltClaims(token);
        return claimsResolver.apply(claims);
    }

    //extract all the attributes  claims from the token as a body [subject,EXPIRATION,....]
    public Claims extracAlltClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] KeyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(KeyBytes);
    }

    // generateToken without pass the claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // generateToken in case pass the claims
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))  // means when this claims was created ( it useful for calculate expirationDate for Token )
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // that means the token is valid for 24 hours plus 1000ms
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();// the thing that will generate and return token with all this information
    }

    // we pass UserDetails to validate if token that passed is  belongs to this user or not
    public boolean isTokenValid (String token , UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);

    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims:: getExpiration);
    }


}
