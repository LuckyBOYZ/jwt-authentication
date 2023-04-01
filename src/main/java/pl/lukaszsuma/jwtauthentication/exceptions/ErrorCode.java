package pl.lukaszsuma.jwtauthentication.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

public enum ErrorCode {

    ERROR_4000(createProblemDetail("No cookies in request",
            "No cookies", HttpStatus.CONFLICT)),
    ERROR_4001(createProblemDetail("No required 'refreshToken' cookie in request",
            "No 'refreshToken'", HttpStatus.CONFLICT)),
    ERROR_4002(createProblemDetail("'refreshToken' cookie has empty value",
            "No value for 'refreshToken'", HttpStatus.CONFLICT)),
    ERROR_4003(createProblemDetail("No record for passed refreshToken",
            "No record in db", HttpStatus.CONFLICT)),
    ERROR_4004(createProblemDetail("No required 'authToken' cookie in request to generate new one",
            "No 'authToken'", HttpStatus.CONFLICT)),
    ERROR_4005(createProblemDetail("Cannot verify authToken signature",
            "Problem while verifying authToken", HttpStatus.CONFLICT)),
    ERROR_4006(createProblemDetail("username from refreshToken and authToken are not the same",
            "Usernames are different", HttpStatus.CONFLICT)),
    ERROR_4007(createProblemDetail("No required 'authToken' cookie in request",
            "No 'authToken'", HttpStatus.CONFLICT));

    private final ProblemDetail problemDetail;

    ErrorCode(ProblemDetail problemDetail) {
        this.problemDetail = problemDetail;
    }

    public ProblemDetail getProblemDetail() {
        return problemDetail;
    }

    private static ProblemDetail createProblemDetail(String detail, String title, HttpStatus httpStatus) {
        ProblemDetail pd = ProblemDetail.forStatus(httpStatus);
        pd.setStatus(httpStatus.value());
        pd.setDetail(detail);
        pd.setTitle(title);
        return pd;
    }
}
