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
 * Class representing principal entry from policy file.
 * 
 * @author Ondrej Lukas
 */
public class ParsedPrincipal {

    private String principalClass = "";
    private String principalName = "";
    private String alias = "";
    private boolean classWildcard = false;
    private boolean nameWildcard = false;
    private boolean isAlias = false;

    /**
     * Constructor for principal from policy file representing by alias in keystore entry.
     * 
     * @param alias alias of principal in keystore entry
     */
    public ParsedPrincipal(String alias) {
        this.alias = alias;
        isAlias = true;
    }

    /**
     * Constructor for classic type of principal in policy file.
     * 
     * @param principalClass name of Principal class or null for wildcard which means every principal class
     * @param principalName name of principal or null for wildcard which means every principal of given Principal class
     */
    public ParsedPrincipal(String principalClass, String principalName) {
        if (principalClass != null) {
            this.principalClass = principalClass;
        } else {
            classWildcard = true;
        }
        if (principalName != null) {
            this.principalName = principalName;
        } else {
            nameWildcard = true;
        }
    }

    /**
     * Getter of Principal class name from principal entry.
     * 
     * @return name of Principal class name from principal entry
     */
    public String getPrincipalClass() {
        return principalClass;
    }

    /**
     * Getter of principal name from principal entry.
     * 
     * @return name of principal from principal entry
     */
    public String getPrincipalName() {
        return principalName;
    }

    /**
     * Getter of principal alias in keystore from principal entry.
     * 
     * @return principal alias in keystore from principal entry
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Method for determining whether principal entry has alias for keystore.
     * 
     * @return true if principal entry has alias for keystore or false if it doesn't have it
     */
    public boolean hasAlias() {
        return isAlias;
    }

    /**
     * Method for determining whether principal entry has wildcard for class name.
     * 
     * @return true if principal entry has wildcard for class name or false if it doesn't have it
     */
    public boolean hasClassWildcard() {
        return classWildcard;
    }

    /**
     * Method for determining whether principal entry has wildcard for principal name.
     * 
     * @return true if principal entry has wildcard for principal name or false if it doesn't have it
     */
    public boolean hasNameWildcard() {
        return nameWildcard;
    }

    @Override
    public String toString() {
        String toReturn = "";
        String toReturnClass = (classWildcard) ? "*" : principalClass;
        String toReturnName = (nameWildcard) ? "*" : principalName;
        if (isAlias) {
            toReturn += "\"" + alias + "\"";
        } else {
            toReturn += toReturnClass + "/" + toReturnName;
        }
        return toReturn;
    }
}
