package pl.lukaszsuma.jwtauthentication.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import pl.lukaszsuma.jwtauthentication.errors.ErrorCode;

import java.io.IOException;
import java.text.ParseException;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Order(Ordered.LOWEST_PRECEDENCE + 1)
@SuppressWarnings("NumericOverflow")
class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Log LOGGER = LogFactory.getLog(JwtAuthenticationFilter.class);
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final AntPathMatcher antPathMatcher;
    private final RSASSAVerifier rsassaVerifier;
    private final ObjectMapper objectMapper;


    @SuppressWarnings({"DataFlowIssue", "DuplicatedCode"})
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            LOGGER.warn(ErrorCode.ERROR_4000.getProblemDetail().getDetail());
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            response.setStatus(ErrorCode.ERROR_4000.getProblemDetail().getStatus());
            this.objectMapper.writeValue(response.getOutputStream(), Map.of("errorMsg",
                    ErrorCode.ERROR_4000.getProblemDetail().getDetail()));
            return;
        }

        String authTokenValue = null;
        for (Cookie cookie : cookies) {
            if ("authToken".equals(cookie.getName())) {
                authTokenValue = cookie.getValue();
            }
        }

        if (ObjectUtils.isEmpty(authTokenValue)) {
            LOGGER.warn(ErrorCode.ERROR_4007.getProblemDetail().getDetail());
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            response.setStatus(ErrorCode.ERROR_4007.getProblemDetail().getStatus());
            this.objectMapper.writeValue(response.getOutputStream(), Map.of("error",
                    ErrorCode.ERROR_4007.getProblemDetail().getDetail()));
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

        String username = jwtService.getSubject(authTokenValue);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails user = userDetailsService.loadUserByUsername(username);
            if (jwtService.isTokenValid(authTokenValue, user)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return this.antPathMatcher.match("/api/v1/auth/**", request.getServletPath());
    }
}
