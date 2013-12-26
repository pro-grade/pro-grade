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
 *
 * @author Ondrej Lukas
 */
public class ParsedKeystoreEntry {

    private String keystoreURL;
    private String keystoreType;
    private String keystoreProvider;

    public ParsedKeystoreEntry(String keystoreURL, String keystoreType, String keystoreProvider) {
        this.keystoreURL = keystoreURL;
        this.keystoreType = keystoreType;
        this.keystoreProvider = keystoreProvider;
    }

    public String getKeystoreURL() {
        return keystoreURL;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public String getKeystoreProvider() {
        return keystoreProvider;
    }

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
