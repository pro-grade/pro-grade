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

/**
 * Class representing keystore entry from policy file.
 * 
 * @author Ondrej Lukas
 */
public class ParsedKeystoreEntry {

    private String keystoreURL;
    private String keystoreType;
    private String keystoreProvider;

    /**
     * @param keystoreURL URL from keystore entry
     * @param keystoreType type from keystore entry
     * @param keystoreProvider provider from keystore entry
     */
    public ParsedKeystoreEntry(String keystoreURL, String keystoreType, String keystoreProvider) {
        this.keystoreURL = keystoreURL;
        this.keystoreType = keystoreType;
        this.keystoreProvider = keystoreProvider;
    }

    /**
     * Getter of URL from keystore entry.
     * 
     * @return URL from keystore entry
     */
    public String getKeystoreURL() {
        return keystoreURL;
    }

    /**
     * Getter of type from keystore entry.
     * 
     * @return type from keystore entry
     */
    public String getKeystoreType() {
        return keystoreType;
    }

    /**
     * Getter of provider from keystore entry.
     * 
     * @return provider from keystore entry
     */
    public String getKeystoreProvider() {
        return keystoreProvider;
    }

    @Override
    public String toString() {
        String toReturn = "";
        toReturn += "KeyStore file: " + keystoreURL;
        if (keystoreType != null) {
            toReturn += ", " + keystoreType;
            if (keystoreProvider != null) {
                toReturn += ", " + keystoreProvider;
            }
        }
        return toReturn;
    }
}
