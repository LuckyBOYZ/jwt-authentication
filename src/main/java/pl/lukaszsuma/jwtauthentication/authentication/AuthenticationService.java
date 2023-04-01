package pl.lukaszsuma.jwtauthentication.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import pl.lukaszsuma.jwtauthentication.config.JwtService;
import pl.lukaszsuma.jwtauthentication.user.Role;
import pl.lukaszsuma.jwtauthentication.user.User;
import pl.lukaszsuma.jwtauthentication.user.UserRepository;
import pl.lukaszsuma.jwtauthentication.utils.RefreshTokenUtils;

import java.time.Instant;
import java.time.InstantSource;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Service
public record AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                                    JwtService jwtService,
                                    AuthenticationManager authenticationManager,
                                    RefreshTokenUtils refreshTokenUtils) {

    public void register(RegisterRequest request) {
        User user = User.builder()
                .firstname(request.firstname())
                .lastname(request.lastname())
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request, HttpServletRequest httpRequest, LocalDateTime now) {
        UsernamePasswordAuthenticationToken authenticate = (UsernamePasswordAuthenticationToken) authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.login(), request.password()));
        authenticate.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        UserDetails principal = (UserDetails) authenticate.getPrincipal();
        String jwt = jwtService.generateToken(principal, now);
        String refreshTokenId = refreshTokenUtils.generateRefreshToken(principal.getUsername(), now);
        AuthenticationResponse response = new AuthenticationResponse(jwt, refreshTokenId);
        return response;
    }
}
