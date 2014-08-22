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
