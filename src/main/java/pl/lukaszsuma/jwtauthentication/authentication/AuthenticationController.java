package pl.lukaszsuma.jwtauthentication.authentication;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Arrays;

@RestController
@RequestMapping("/api/v1/auth")
public record AuthenticationController(AuthenticationService authenticationService) {

    @PostMapping("/register")
    ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        authenticationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/authenticate")
    ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request,
                                                        HttpServletResponse response, HttpServletRequest httpRequest) {
        Cookie[] cookies = httpRequest.getCookies();
        if (cookies != null) {
            Arrays.stream(cookies).forEach(cookie -> System.out.println(cookie.getMaxAge()));
        } else {
            System.out.println("Cookies are null");
        }
        LocalDateTime now = LocalDateTime.now();
        AuthenticationResponse user = authenticationService.authenticate(request, httpRequest, now);
        AuthenticationResponse authenticate = user;
        ResponseCookie authCookie = createTokenCookie("authToken", authenticate.authToken());
        ResponseCookie refreshCookie = createTokenCookie("refreshToken", authenticate.refreshToken());
        response.addHeader(HttpHeaders.SET_COOKIE, authCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        /**
         * zwrocic imie, nazwisko, role,
         */
        return ResponseEntity.ok().build();
    }

    private ResponseCookie createTokenCookie(String cookieName, String token) {
        ResponseCookie rc = ResponseCookie.from(cookieName)
                .httpOnly(true)
//                .sameSite(org.springframework.boot.web.server.Cookie.SameSite.NONE.attributeValue())
                .sameSite(org.springframework.boot.web.server.Cookie.SameSite.LAX.attributeValue())
                .secure(false)
                .path("/")
                .maxAge(60*60).value(token).build();
        return rc;
    }

    @PostMapping("/refreshtoken")
    ResponseEntity<String> refreshToken() {
        return ResponseEntity.ok("Jestes w metodzie refreshToken");
    }
}
