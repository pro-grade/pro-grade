package net.sourceforge.prograde.type;

import java.util.Locale;

public enum Priority {
    GRANT, DENY;

    public static final Priority DEFAULT = DENY;

    @Override
    public String toString() {
        return name().toLowerCase(Locale.ENGLISH);
    }

}
