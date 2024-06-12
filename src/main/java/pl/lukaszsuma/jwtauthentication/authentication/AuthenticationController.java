package pl.lukaszsuma.jwtauthentication.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.server.Cookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;

@RestController
@RequestMapping("/api/v1/auth")
public record AuthenticationController(AuthenticationService authenticationService) {

    private static final ZonedDateTime TIME_ZONES_DIFF = Instant.now().atZone(ZoneId.of("Europe/Warsaw"));

    @PostMapping("/register")
    ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        authenticationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/authenticate")
    ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request,
                                                        HttpServletResponse response, HttpServletRequest httpRequest) {
        LocalDateTime now = LocalDateTime.now();
        AuthenticationResponse user = authenticationService.authenticate(request, httpRequest, now);
//        Cookie authToken = createTokenCookie("authToken", user.authToken(), 3600);
//        Cookie refreshToken = createTokenCookie("refreshToken", user.refreshToken(), 7200);
//        response.addCookie(authToken);
//        response.addCookie(refreshToken);
        ResponseCookie authToken = createTokenCookie("authToken", user.authToken(), 3600);
        ResponseCookie refreshToken = createTokenCookie("refreshToken", user.refreshToken(), 7200);
        response.addHeader(HttpHeaders.SET_COOKIE, authToken.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshToken.toString());
        /**
         * zwrocic imie, nazwisko, role,
         */
        return ResponseEntity.ok().build();
    }

    private ResponseCookie createTokenCookie(String cookieName, String token, int maxAge) {
//        jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie(cookieName, token);
//        cookie.setPath("/");
//        cookie.setMaxAge(Instant.now().atZone(ZoneId.of("Europe/Warsaw")).getOffset().getTotalSeconds() + maxAge);
//        cookie.setHttpOnly(true);
//        cookie.setSecure(true);
//        cookie.setAttribute("SameSite", "None");

        ResponseCookie rc = ResponseCookie.from(cookieName, token)
                .httpOnly(true)
                .sameSite(Cookie.SameSite.NONE.attributeValue())
                .secure(true)
                .path("/")
                .maxAge(TIME_ZONES_DIFF.getOffset().getTotalSeconds() + maxAge)
                .build();
        return rc;
//        return cookie;
    }

    @PostMapping("/refreshtoken")
    ResponseEntity<String> refreshToken() {
        return ResponseEntity.ok("Jestes w metodzie refreshToken");
    }
}
