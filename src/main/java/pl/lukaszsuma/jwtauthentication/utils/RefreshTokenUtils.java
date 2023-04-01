package pl.lukaszsuma.jwtauthentication.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pl.lukaszsuma.jwtauthentication.refreshtoken.RefreshToken;
import pl.lukaszsuma.jwtauthentication.refreshtoken.RefreshTokenRepository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenUtils {

    private final RefreshTokenRepository repository;
    private final TimeUtils timeUtils;

    @Value("${app.refresh-token-expiry-time}")
    private long refreshTokenExpiryTime;

    public String generateRefreshToken(String username, LocalDateTime now) {
        Optional<RefreshToken> record = repository.findByUsername(username);
        if (record.isPresent()) {
            return record.get().getId();
        }
        RefreshToken refreshToken = new RefreshToken(UUID.randomUUID().toString(),
                timeUtils.getEpochFromLocalDateTimeAndAdditionalTime(now, refreshTokenExpiryTime), username, true);
        repository.save(refreshToken);
        return refreshToken.getId();
    }
}
