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
public class ParsedPermission {

    private String permissionType;
    private String permissionName;
    private String actions;
    private String signedBy;

    public String getPermissionType() {
        return permissionType;
    }

    public void setPermissionType(String permissionType) {
        this.permissionType = permissionType;
    }

    public String getPermissionName() {
        return permissionName;
    }

    public void setPermissionName(String permissionName) {
        this.permissionName = permissionName;
    }

    public String getActions() {
        return actions;
    }

    public void setActions(String actions) {
        this.actions = actions;
    }

    public String getSignedBy() {
        return signedBy;
    }

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
