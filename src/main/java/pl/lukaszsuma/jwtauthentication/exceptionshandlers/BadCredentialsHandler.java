package pl.lukaszsuma.jwtauthentication.exceptionshandlers;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import pl.lukaszsuma.jwtauthentication.errors.ErrorCode;
import pl.lukaszsuma.jwtauthentication.errors.ErrorUtils;

import java.io.IOException;

@ControllerAdvice
record BadCredentialsHandler(ErrorUtils errorUtils) {

    @ExceptionHandler(BadCredentialsException.class)
    void badCredentialsException(HttpServletResponse response) throws IOException {
        errorUtils.generateErrorResponse(ErrorCode.ERROR_4008, response);
    }

}
