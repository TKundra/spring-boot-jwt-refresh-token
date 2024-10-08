package com.learning.advice;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.security.SignatureException;

@RestControllerAdvice
public class CustomExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        ProblemDetail errorDetail = null;
        if (exception instanceof BadCredentialsException) {
            errorDetail = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(401),
                    exception.getMessage()
            );
            errorDetail.setProperty("access_denied_reason", "Authentication Failure");
        }

        if (exception instanceof RuntimeException) {
            errorDetail = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(500),
                    exception.getMessage()
            );
            errorDetail.setProperty("access_denied_reason", "Something Went Wrong");
        }

        if (exception instanceof BadCredentialsException) {
            errorDetail = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    exception.getMessage()
            );
            errorDetail.setProperty("access_denied_reason", "Unauthorized");
        }

        if (exception instanceof SignatureException) {
            errorDetail = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    exception.getMessage()
            );
            errorDetail.setProperty("access_denied_reason", "JWT Signature not valid");
        }

        if (exception instanceof ExpiredJwtException) {
            errorDetail = ProblemDetail.forStatusAndDetail(
                    HttpStatusCode.valueOf(403),
                    exception.getMessage()
            );
            errorDetail.setProperty("access_denied_reason", "JWT Token already expired !");
        }

        return errorDetail;
    }
}
