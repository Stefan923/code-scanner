import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;

public class CSRFVulnerableClass extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        if ("delete".equals(action)) {
            response.getWriter().println("Account deleted.");
        } else {
            response.getWriter().println("No action performed.");
        }
        URL url = new URL(action);
        Runtime.getRuntime().exec(request.getParameter("command"));
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        doPost(request, response);
    }
}
