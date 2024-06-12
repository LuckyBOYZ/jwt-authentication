package pl.lukaszsuma.jwtauthentication.errors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
public record ErrorUtils(ObjectMapper objectMapper) {

    @SuppressWarnings("DataFlowIssue")
    public void generateErrorResponse(ErrorCode errorCode, HttpServletResponse response) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON.toString());
        response.setStatus(errorCode.getProblemDetail().getStatus());
        this.objectMapper.writeValue(response.getOutputStream(), Map.of("error",
                errorCode.getProblemDetail().getDetail()));
    }
}
