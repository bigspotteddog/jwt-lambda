package com.nobodyelses.jwt;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class JwtTest
{
  @Test
  public void testJwt() {
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    long nowMillis = System.currentTimeMillis();
    Date now = new Date(nowMillis);

    int ONE_DAY = 24 * 60 * 60 * 1000;
    long ttlMillis = ONE_DAY;

    SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    byte[] apiKeySecretBytes = secretKey.getEncoded();
    Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

    JwtBuilder builder = Jwts.builder().setId("id")
        .setIssuedAt(now)
        .setSubject("subject")
        .setIssuer("issuer")
        .signWith(signingKey, signatureAlgorithm);

    if (ttlMillis > 0) {
      long expMillis = nowMillis + ttlMillis;
      Date exp = new Date(expMillis);
      builder.setExpiration(exp);
    }

    String jws = builder.compact();

    Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(signingKey).build().parseClaimsJws(jws);

    assertNotNull(claims);
  }
}
