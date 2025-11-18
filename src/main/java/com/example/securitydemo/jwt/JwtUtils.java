package com.example.securitydemo.jwt;




import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {
	
	private static final Logger log=LoggerFactory.getLogger(JwtUtils.class);
	
	@Value("${spring.app.jwtExpirationMs}")
	 private int jwtExpirationMs;
	
	@Value("${spring.app.jwtSecret}")
	 private String jwtSecret;
	
	
	//Getting JWT From Header
	public String getJwtFromHeader(HttpServletRequest request) {
		String bearerToken =request.getHeader("Authorization");
		log.debug("Authorization Header: {} ",bearerToken);
		if(bearerToken !=null && bearerToken.startsWith("Bearer")) {
			return bearerToken.substring(7);//Remove Bearer Prfix
		}
		return null;
	}
	
	//Generating Token from Username
	public String generateTokenFromUsername(UserDetails userDetails ) {
		String username=userDetails.getUsername();
		return Jwts.builder()
				.subject(username)
				.issuedAt(new Date())
				.expiration(new Date((new Date().getTime() + jwtExpirationMs)))
				.signWith(key())
				.compact();
	}
	
	//Getting Username from JWT Token
	public String getUserNameFromJWTToken(String token) {
		return Jwts.parser()
				.verifyWith((SecretKey) key())
				.build().parseSignedClaims(token)
				.getPayload().getSubject();
	}
	
	//Generate Signing Key
	public Key key() {
		return Keys.hmacShaKeyFor(
				Decoders.BASE64.decode(jwtSecret)
				);
		
	}
	
	
	//Validation JWT Token
	
	public boolean validateJwtToken(String authToken) {
		try {
			System.out.println("Validate");
			Jwts.parser()
			.verifyWith((SecretKey) key())
			.build()
			.parseSignedClaims(authToken);
			
			return true;
		}
		catch(MalformedJwtException e) {
			log.error("Invalid JWT token {}",e.getMessage());
		}
		catch(ExpiredJwtException e) {
			log.error("ExpiredJwtException {}",e.getMessage());
		}
		catch(UnsupportedJwtException e) {
			log.error("UnsupportedJwtException {}",e.getMessage());
		}
		catch(IllegalArgumentException e) {
			log.error("IllegalArgumentException {}",e.getMessage());
		}
		return false;
	}
	

}
