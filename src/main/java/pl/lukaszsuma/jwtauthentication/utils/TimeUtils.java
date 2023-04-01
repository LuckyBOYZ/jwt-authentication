package pl.lukaszsuma.jwtauthentication.utils;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

@Component
public class TimeUtils {

    public LocalDateTime getLocalDateTimeFromEpoch(long epochTime) {
//        LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) <- epoch bez zmiany strefy
        return LocalDateTime.ofEpochSecond(epochTime, 0, ZoneOffset.UTC);
    }

    public long getEpochFromLocalDateTimeAndAdditionalTime(LocalDateTime time, long minutesToAdd) {
        return time.plus(minutesToAdd, ChronoUnit.MINUTES).toEpochSecond(ZoneOffset.UTC);
    }

    public Instant getInstantFromLocalDateTimeAndAdditionalTime(LocalDateTime time, long minutesToAdd) {
        return time.plus(minutesToAdd, ChronoUnit.MINUTES).toInstant(ZoneOffset.UTC);
    }

}
