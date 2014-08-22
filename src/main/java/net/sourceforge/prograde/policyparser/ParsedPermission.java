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
 * Class representing permission entry from policy file.
 * 
 * @author Ondrej Lukas
 */
public class ParsedPermission {

    private String permissionType;
    private String permissionName;
    private String actions;
    private String signedBy;

    /**
     * Getter of type from permission entry.
     * 
     * @return type from permission entry
     */
    public String getPermissionType() {
        return permissionType;
    }

    /**
     * Setter of type from permission entry.
     * 
     * @param permissionType type from permission entry
     */
    public void setPermissionType(String permissionType) {
        this.permissionType = permissionType;
    }

    /**
     * Getter of name from permission entry.
     * 
     * @return name from permission entry
     */
    public String getPermissionName() {
        return permissionName;
    }

    /**
     * Setter of name from permission entry.
     * 
     * @param permissionName name from permission entry
     */
    public void setPermissionName(String permissionName) {
        this.permissionName = permissionName;
    }

    /**
     * Getter of actions from permission entry.
     * 
     * @return actions from permission entry
     */
    public String getActions() {
        return actions;
    }

    /**
     * Setter of actions from permission entry.
     * 
     * @param actions actions from permission entry
     */
    public void setActions(String actions) {
        this.actions = actions;
    }

    /**
     * Getter of signedBy from permission entry.
     * 
     * @return signedBy from permission entry
     */
    public String getSignedBy() {
        return signedBy;
    }

    /**
     * Setter of signedBy from permission entry.
     * 
     * @param signedBy signedBy from permission entry
     */
    public void setSignedBy(String signedBy) {
        this.signedBy = signedBy;
    }

    @Override
    public String toString() {
        String toReturn = "";
        String toReturnPermissionType = (permissionType == null) ? "undefined" : permissionType;
        toReturn += "( \"" + toReturnPermissionType + "\"";
        if (permissionName != null) {
            toReturn += ", \"" + permissionName + "\"";
            if (actions != null) {
                toReturn += ", \"" + actions + "\"";
            }
        }
        if (signedBy != null) {
            toReturn += ", \"" + signedBy + "\"";
        }
        toReturn += " )\n";
        return toReturn;
    }
}
