package exception;

public class InvalidCSRFTokenException extends RuntimeException {
    public InvalidCSRFTokenException(String message) {
        super(message);
    }
}
