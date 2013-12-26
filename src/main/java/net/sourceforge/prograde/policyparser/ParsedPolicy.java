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

    public ParsedPolicy(List<ParsedPolicyEntry> grantEntries, List<ParsedPolicyEntry> denyEntries, ParsedKeystoreEntry keystore, String keystorePasswordURL,
            File policyFile) {
        this(grantEntries, denyEntries, keystore, keystorePasswordURL, policyFile, false);
    }

    public ParsedPolicy(List<ParsedPolicyEntry> grantEntries, List<ParsedPolicyEntry> denyEntries, ParsedKeystoreEntry keystore, String keystorePasswordURL,
            File policyFile, boolean priority) {
        this.grantEntries = grantEntries;
        this.denyEntries = denyEntries;
        this.keystore = keystore;
        this.keystorePasswordURL = keystorePasswordURL;
        this.policyFile = policyFile;
        this.priority = priority;
    }

    public List<ParsedPolicyEntry> getGrantEntries() {
        return grantEntries;
    }

    public List<ParsedPolicyEntry> getDenyEntries() {
        return denyEntries;
    }

    public String getKeystorePasswordURL() {
        return keystorePasswordURL;
    }

    public ParsedKeystoreEntry getKeystore() {
        return keystore;
    }

    public boolean getPriority() {
        return priority;
    }

    public URL getPolicyURL() {
        return policyURL;
    }

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
