package net.sourceforge.prograde.debug;

/**
 * Class for printing debug information.
 * 
 * @author Ondrej Lukas
 */
public class ProgradePolicyDebugger {

    /**
     * Method for printing debug information to standard output. Method adds "Policy: " before message for printing.
     * 
     * @param log message for printing
     */
    public static void log(String log) {
        System.out.println("Policy: " + log);
    }
}
