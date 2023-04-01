package pl.lukaszsuma.jwtauthentication.exceptionshandlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.Map;

@ControllerAdvice
record DuplicatedEntryHandler(ObjectMapper objectMapper) {

    @ExceptionHandler(SQLIntegrityConstraintViolationException.class)
    @SuppressWarnings("unchecked")
    ProblemDetail sqlIntegrityConstraintViolationException(ContentCachingRequestWrapper request) throws IOException {
        String bodyAsString = new String(request.getContentAsByteArray());
        Map<String, String> parsedBody = this.objectMapper.readValue(bodyAsString, Map.class);
        String username = parsedBody.get("username");
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.CONFLICT);
        pd.setDetail(String.format("User '%s' already exist", username));
        return pd;
    }
}
