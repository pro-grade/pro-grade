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
