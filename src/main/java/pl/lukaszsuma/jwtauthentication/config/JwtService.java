package pl.lukaszsuma.jwtauthentication.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import pl.lukaszsuma.jwtauthentication.utils.TimeUtils;

import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.InstantSource;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public record JwtService(RSAPrivateKey privateKey, RSASSASigner rsassaSigner, TimeUtils timeUtils) {

    @Value("${app.jwt-expiry-time}")
    private static long jwtExpiryTime;

    public String getSubject(String token) {
        return getValueFromClaim(token, JWTClaimsSet::getSubject);
    }

    public String generateToken(UserDetails user, LocalDateTime time) {
        return generateToken(Collections.emptyMap(), user, time);
    }

    public String generateToken(Map<String, Object> extractClaims, UserDetails user, LocalDateTime time) {
        Date now = Date.from(time.toInstant(ZoneOffset.UTC));
        // @formatter:off
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID(null)
                .build();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer(user.getUsername())
                .issueTime(now)
                .expirationTime(Date.from(timeUtils.getInstantFromLocalDateTimeAndAdditionalTime(time, jwtExpiryTime)));
        extractClaims.forEach(builder::claim);
        JWTClaimsSet payload = builder.build();
        // @formatter:on

        SignedJWT signedJWT = new SignedJWT(header, payload);
        try {
            signedJWT.sign(this.rsassaSigner);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT.serialize();
    }

    public boolean isTokenValid(String token, UserDetails user) {
        String username = getSubject(token);
        return username.equals(user.getUsername()) && isTokenExpired(token);
    }

    public <T> T getValueFromClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public JWTClaimsSet extractAllClaims(String token) {
        try {
            final SignedJWT decodedJwt = SignedJWT.parse(token);
            return decodedJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).after(Date.from(InstantSource.system().instant()));
    }

    private Date extractExpiration(String token) {
        return getValueFromClaim(token, JWTClaimsSet::getExpirationTime);
    }
}
