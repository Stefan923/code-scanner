import java.io.FileWriter;
import java.io.IOException;

public class XSSExtended {
    public static void writeToFile(String youAreDumb) {
        try (FileWriter writer = new FileWriter("vulnerableOutput.html", true)) {
            writer.write("<div>" + youAreDumb + "</div>\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
