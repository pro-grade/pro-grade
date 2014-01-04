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

import java.util.ArrayList;
import java.util.List;

/**
 * Class representing one policy (grant or deny) entry from policy file.
 * 
 * @author Ondrej Lukas
 */
public class ParsedPolicyEntry {

    private String codebase;
    private String signedBy;
    private List<ParsedPrincipal> principals = new ArrayList<ParsedPrincipal>();
    private List<ParsedPermission> permissions = new ArrayList<ParsedPermission>();

    /**
     * Getter of codebase from policy entry.
     * 
     * @return codebase from policy entry
     */
    public String getCodebase() {
        return codebase;
    }

    /**
     * Setter of codebase from policy entry.
     * 
     * @param codebase codebase from policy entry
     */
    public void setCodebase(String codebase) {
        this.codebase = codebase;
    }

    /**
     * Getter of signedBy from policy entry.
     * 
     * @return signedBy from policy entry
     */
    public String getSignedBy() {
        return signedBy;
    }

    /**
     * Setter of signedBy from policy entry.
     * 
     * @param signedBy signedBy from policy entry
     */
    public void setSignedBy(String signedBy) {
        this.signedBy = signedBy;
    }

    /**
     * Getter of principals from policy entry which are represented by list of ParsedPrincipal.
     * 
     * @return list of ParsedPrincipal from policy entry
     */
    public List<ParsedPrincipal> getPrincipals() {
        return principals;
    }

    /**
     * Add principal from policy entry represented by ParsedPrincipal to this ParsedPolicyEntry.
     * 
     * @param principal principal from policy entry for adding
     */
    public void addPrincipal(ParsedPrincipal principal) {
        principals.add(principal);
    }

    /**
     * Getter of permissions from policy entry which are represented by list of ParsedPermission.
     * 
     * @return list of ParsedPermission from policy entry
     */
    public List<ParsedPermission> getPermissions() {
        return permissions;
    }

    /**
     * Add permission from policy entry represented by ParsedPermission to this ParsedPolicyEntry.
     * 
     * @param perm permission from policy entry for adding
     */
    public void addPermission(ParsedPermission perm) {
        permissions.add(perm);
    }

    @Override
    public String toString() {
        String toReturn = "";
        String toReturnCodebase = (codebase == null) ? "undefined" : codebase;
        String toReturnSignedBy = (signedBy == null) ? "undefined" : signedBy;
        toReturn += "Codebase: " + toReturnCodebase + ", Signed By: " + toReturnSignedBy + ", Principals: { ";
        int counter = 0;
        for (ParsedPrincipal p : principals) {
            if (counter != 0) {
                toReturn += ", ";
            }
            toReturn += p.toString();
            counter++;
        }
        if (principals.isEmpty()) {
            toReturn += "undefined";
        }
        toReturn += " }\n";
        toReturn += "permissions: \n";
        for (ParsedPermission p : permissions) {
            toReturn += "  " + p.toString();
        }
        return toReturn;
    }
}
