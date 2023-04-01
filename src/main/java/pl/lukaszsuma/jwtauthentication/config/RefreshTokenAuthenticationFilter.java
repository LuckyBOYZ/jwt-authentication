package pl.lukaszsuma.jwtauthentication.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import pl.lukaszsuma.jwtauthentication.exceptions.ErrorCode;
import pl.lukaszsuma.jwtauthentication.refreshtoken.RefreshToken;
import pl.lukaszsuma.jwtauthentication.refreshtoken.RefreshTokenRepository;

import java.io.IOException;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Order(Ordered.LOWEST_PRECEDENCE + 2)
@SuppressWarnings("NumericOverflow")
class RefreshTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Log LOGGER = LogFactory.getLog(RefreshTokenAuthenticationFilter.class);
    private final AntPathMatcher antPathMatcher;
    private final ObjectMapper objectMapper;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RSASSAVerifier rsassaVerifier;

    @SuppressWarnings({"DataFlowIssue", "DuplicatedCode"})
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            LOGGER.warn(ErrorCode.ERROR_4001.getProblemDetail().getDetail());
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            response.setStatus(ErrorCode.ERROR_4001.getProblemDetail().getStatus());
            this.objectMapper.writeValue(response.getOutputStream(), Map.of("error",
                    ErrorCode.ERROR_4001.getProblemDetail().getDetail()));
            return;
        }
        String refreshTokenValue = null;
        for (Cookie cookie : cookies) {
            if ("refreshToken".equals(cookie.getName())) {
                refreshTokenValue = cookie.getValue();
            }
        }

        if (ObjectUtils.isEmpty(refreshTokenValue)) {
            LOGGER.warn(ErrorCode.ERROR_4002.getProblemDetail().getDetail());
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            response.setStatus(ErrorCode.ERROR_4002.getProblemDetail().getStatus());
            this.objectMapper.writeValue(response.getOutputStream(), Map.of("error",
                    ErrorCode.ERROR_4002.getProblemDetail().getDetail()));
            return;
        }

        String authTokenValue = null;
        for (Cookie cookie : cookies) {
            if ("authToken".equals(cookie.getName())) {
                authTokenValue = cookie.getValue();
            }
        }

        if (ObjectUtils.isEmpty(authTokenValue)) {
            LOGGER.warn(ErrorCode.ERROR_4004.getProblemDetail().getDetail());
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            response.setStatus(ErrorCode.ERROR_4004.getProblemDetail().getStatus());
            this.objectMapper.writeValue(response.getOutputStream(), Map.of("error",
                    ErrorCode.ERROR_4004.getProblemDetail().getDetail()));
            return;
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(authTokenValue);
            this.rsassaVerifier.verify(signedJWT.getHeader(), signedJWT.getSigningInput(), signedJWT.getSignature());
        } catch (ParseException | JOSEException ex) {
            LOGGER.warn(ErrorCode.ERROR_4005.getProblemDetail().getDetail(), ex);
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            response.setStatus(ErrorCode.ERROR_4005.getProblemDetail().getStatus());
            this.objectMapper.writeValue(response.getOutputStream(), Map.of("error",
                    ErrorCode.ERROR_4005.getProblemDetail().getDetail()));
            return;
        }

        Optional<RefreshToken> refreshTokenFromDb = refreshTokenRepository.findById(refreshTokenValue);

        if (refreshTokenFromDb.isEmpty()) {
            LOGGER.warn(String.format("No record for id %s", refreshTokenValue));
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            response.setStatus(ErrorCode.ERROR_4003.getProblemDetail().getStatus());
            this.objectMapper.writeValue(response.getOutputStream(), Map.of("error",
                    ErrorCode.ERROR_4003.getProblemDetail().getDetail()));
            return;
        }

        RefreshToken refreshToken = refreshTokenFromDb.get();
        String username = refreshToken.getUsername();

        String usernameFromJwt = getUsernameFromJwt(signedJWT);
        if (ObjectUtils.isEmpty(usernameFromJwt) && !usernameFromJwt.equals(username)) {
            LOGGER.warn(ErrorCode.ERROR_4006.getProblemDetail().getDetail());
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            response.setStatus(ErrorCode.ERROR_4006.getProblemDetail().getStatus());
            this.objectMapper.writeValue(response.getOutputStream(), Map.of("error",
                    ErrorCode.ERROR_4006.getProblemDetail().getDetail()));
            return;
        }
        filterChain.doFilter(request, response);
    }

    @SneakyThrows
    private String getUsernameFromJwt(SignedJWT signedJWT) {
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        return jwtClaimsSet.getSubject();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String extractPath = antPathMatcher.extractPathWithinPattern("/api/**/auth/**", request.getServletPath());
        String[] split = extractPath.split("/");
        String refreshToken = split[split.length - 1];
        return !"refreshToken".equals(refreshToken);
    }


}
