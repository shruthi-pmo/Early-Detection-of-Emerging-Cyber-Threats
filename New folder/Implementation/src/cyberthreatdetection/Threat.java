
package cyberthreatdetection;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Threat {

    private final int id;
    private final String name;
    private final String category;
    private final String severity;
    private final String date;

    public Threat(int id, String name, String category, String severity) {
        this(id, name, category, severity,
                LocalDateTime.now().format(
                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
    }

    public Threat(int id, String name, String category,
                  String severity, String date) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.severity = severity;
        this.date = date;
    }

    public int getId() { return id; }
    public String getName() { return name; }
    public String getCategory() { return category; }
    public String getSeverity() { return severity; }
    public String getDate() { return date; }
}
