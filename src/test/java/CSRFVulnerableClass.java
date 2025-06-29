import exception.InvalidCSRFTokenException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CSRFVulnerableClass extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        if ("delete".equals(action)) {
            response.getWriter().println("Account deleted.");
        } else {
            response.getWriter().println("No action performed.");
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        validateCsrfToken(request, response);
        doPost(request, response);
    }

    private void validateCsrfToken(HttpServletRequest request, HttpServletResponse ignoredResponse) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals("csrfToken")) {
                    return;
                }
            }
        }
        throw new InvalidCSRFTokenException("CSRF token is not valid");
    }
}
