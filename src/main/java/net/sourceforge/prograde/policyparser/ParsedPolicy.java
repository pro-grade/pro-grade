package net.sourceforge.prograde.policyparser;

import java.net.URL;
import java.util.List;

import net.sourceforge.prograde.type.Priority;

/**
 * Class representing parsed policy file.
 * 
 * @author Ondrej Lukas
 */
public class ParsedPolicy {

    private List<ParsedPolicyEntry> grantEntries;
    private List<ParsedPolicyEntry> denyEntries;
    private String keystorePasswordURL;
    private ParsedKeystoreEntry keystore;
    private Priority priority;
    private URL policyURL;

    /**
     * Constructor for ParsedPolicy with default priority
     * 
     * @param grantEntries list of grant entries
     * @param denyEntries list of deny entries
     * @param keystore keystore entry
     * @param keystorePasswordURL keystore password URL
     * @param policyFile file with this parsed policy file
     */
    public ParsedPolicy(List<ParsedPolicyEntry> grantEntries, List<ParsedPolicyEntry> denyEntries,
            ParsedKeystoreEntry keystore, String keystorePasswordURL) {
        this(grantEntries, denyEntries, keystore, keystorePasswordURL, null);
    }

    /**
     * Constructor for ParsedPolicy.
     * 
     * @param grantEntries list of grant entries
     * @param denyEntries list of deny entries
     * @param keystore keystore entry
     * @param keystorePasswordURL keystore password URL
     * @param policyFile file with this parsed policy file
     * @param priority priority of entries
     */
    public ParsedPolicy(List<ParsedPolicyEntry> grantEntries, List<ParsedPolicyEntry> denyEntries,
            ParsedKeystoreEntry keystore, String keystorePasswordURL, Priority priority) {
        this.grantEntries = grantEntries;
        this.denyEntries = denyEntries;
        this.keystore = keystore;
        this.keystorePasswordURL = keystorePasswordURL;
        this.priority = priority;
    }

    /**
     * Getter of grant entries from policy file which are represented by list of ParsedPolicyEntry.
     * 
     * @return list of grant ParsedPrincipal from policy file
     */
    public List<ParsedPolicyEntry> getGrantEntries() {
        return grantEntries;
    }

    /**
     * Getter of deny entries from policy file which are represented by list of ParsedPolicyEntry.
     * 
     * @return list of deny ParsedPrincipal from policy file
     */
    public List<ParsedPolicyEntry> getDenyEntries() {
        return denyEntries;
    }

    /**
     * Getter of keystorePasswordURL from policy file.
     * 
     * @return keystorePasswordURL from policy file
     */
    public String getKeystorePasswordURL() {
        return keystorePasswordURL;
    }

    /**
     * Getter of keystore represented by ParsedKeystoreEntry from policy file.
     * 
     * @return keystore from policy file
     */
    public ParsedKeystoreEntry getKeystore() {
        return keystore;
    }

    /**
     * Getter of priority from policy file.
     * 
     * @return the priority
     */
    public Priority getPriority() {
        return priority;
    }

    /**
     * Getter of URL of file with policy file.
     * 
     * @return URL of file with policy file
     */
    public URL getPolicyURL() {
        return policyURL;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Grant entries:\n");
        for (ParsedPolicyEntry p : grantEntries) {
            sb.append(p.toString());
            sb.append("\n");
        }
        sb.append("Deny entries:\n");
        for (ParsedPolicyEntry p : denyEntries) {
            sb.append(p.toString());
            sb.append("\n");
        }
        sb.append("\n");
        sb.append("Keystore: ");
        if (keystore != null) {
            sb.append(keystore.toString());
        } else {
            sb.append("undefined");
        }
        sb.append("\n");
        sb.append("Keystore Password URL: ");
        if (keystorePasswordURL != null) {
            sb.append(keystorePasswordURL.toString());
        } else {
            sb.append("undefined");
        }
        sb.append("\n");
        sb.append("Priority: ");
        sb.append(priority);
        return sb.toString();
    }
}
