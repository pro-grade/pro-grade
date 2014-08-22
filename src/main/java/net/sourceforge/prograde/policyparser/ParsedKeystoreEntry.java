/*
 * #%L
 * pro-grade
 * %%
 * Copyright (C) 2013 - 2014 Ondřej Lukáš, Josef Cacek
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
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
