
package cyberthreatdetection;

import java.time.LocalDate;

public class Threat {

    int id;
    String name;
    String category;
    String severity;
    LocalDate date;

    public Threat(int id, String name, String category, String severity) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.severity = severity;
        this.date = LocalDate.now();
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getCategory() {
        return category;
    }

    public String getSeverity() {
        return severity;
    }

    public LocalDate getDate() {
        return date;
    }
}