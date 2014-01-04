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
