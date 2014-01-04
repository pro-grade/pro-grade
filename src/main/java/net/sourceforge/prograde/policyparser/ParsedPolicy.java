/** Copyright 2013 Ondrej Lukas
  *
  * This file is part of pro-grade.
  *
  * Pro-grade is free software: you can redistribute it and/or modify
  * it under the terms of the GNU Lesser General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * (at your option) any later version.
  *
  * Pro-grade is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public License
  * along with pro-grade.  If not, see <http://www.gnu.org/licenses/>.
  *
  */
package net.sourceforge.prograde.policyparser;

import java.io.File;
import java.net.URL;
import java.util.List;

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
    private boolean priority;
    private URL policyURL;
    private File policyFile;

    /**
     * Constructor for ParsedPolicy with predefined priority (set to false which means denying priority).
     * 
     * @param grantEntries list of grant entries
     * @param denyEntries list of deny entries
     * @param keystore keystore entry
     * @param keystorePasswordURL keystore password URL
     * @param policyFile file with this parsed policy file
     */
    public ParsedPolicy(List<ParsedPolicyEntry> grantEntries, List<ParsedPolicyEntry> denyEntries, ParsedKeystoreEntry keystore, String keystorePasswordURL,
            File policyFile) {
        this(grantEntries, denyEntries, keystore, keystorePasswordURL, policyFile, false);
    }

    /**
     * Constructor for ParsedPolicy.
     * 
     * @param grantEntries list of grant entries
     * @param denyEntries list of deny entries
     * @param keystore keystore entry
     * @param keystorePasswordURL keystore password URL
     * @param policyFile file with this parsed policy file
     * @param priority priority of entries, true means priority grant, false means priority deny
     */
    public ParsedPolicy(List<ParsedPolicyEntry> grantEntries, List<ParsedPolicyEntry> denyEntries, ParsedKeystoreEntry keystore, String keystorePasswordURL,
            File policyFile, boolean priority) {
        this.grantEntries = grantEntries;
        this.denyEntries = denyEntries;
        this.keystore = keystore;
        this.keystorePasswordURL = keystorePasswordURL;
        this.policyFile = policyFile;
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
     * @return true for priority grant, false for priority deny
     */
    public boolean getPriority() {
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

    /**
     * Getter of file with policy file.
     * 
     * @return file with policy file
     */
    public File getPolicyFile() {
        return policyFile;
    }

    @Override
    public String toString() {
        String toReturn = "";
        toReturn += "Grant entries:\n";
        for (ParsedPolicyEntry p : grantEntries) {
            toReturn += p.toString();
            toReturn += "\n";
        }
        toReturn += "Deny entries:\n";
        for (ParsedPolicyEntry p : denyEntries) {
            toReturn += p.toString();
            toReturn += "\n";
        }
        toReturn += "\n";
        toReturn += "Keystore: ";
        if (keystore != null) {
            toReturn += keystore.toString();
        } else {
            toReturn += "undefined";
        }
        toReturn += "\n";
        toReturn += "Keystore Password URL: ";
        if (keystorePasswordURL != null) {
            toReturn += keystorePasswordURL.toString();
        } else {
            toReturn += "undefined";
        }
        toReturn += "\n";
        toReturn += "Priority: ";
        toReturn += (priority) ? "grant" : "deny";
        return toReturn;
    }
}
