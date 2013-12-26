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
package net.sourceforge.prograde.policy;

import java.security.CodeSource;
import java.security.Permission;
import java.security.Permissions;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import net.sourceforge.prograde.debug.ProgradePolicyDebugger;

/**
 *
 * @author Ondrej Lukas
 */
public class ProgradePolicyEntry {

    private CodeSource codeSource; // codebase + cert gained from signedby
    private List<ProgradePrincipal> principals;
    private Permissions permissions;
    private boolean neverImplies = false;
    private boolean debug = false;
    // this is only for debug
    private boolean grant;

    public ProgradePolicyEntry(boolean grant, boolean debug) {
        principals = new ArrayList<ProgradePrincipal>();
        permissions = new Permissions();
        this.grant = grant;
        this.debug = debug;
    }

    public void setCodeSource(CodeSource codeSource) {
        this.codeSource = codeSource;
    }

    public void addPrincipal(ProgradePrincipal principal) {
        principals.add(principal);
    }

    public void addPermission(Permission permission) {
        permissions.add(permission);
    }

    public void setNeverImplies(boolean neverImplies) {
        this.neverImplies = neverImplies;
    }

    public boolean implies(ProtectionDomain pd, Permission permission) {

        if (neverImplies) {
            if (debug) {
                ProgradePolicyDebugger.log("This entry never imply anything.");
            }
            return false;
        }

        // codesource
        if (codeSource != null && pd.getCodeSource() != null) {
            if (debug) {
                ProgradePolicyDebugger.log("Evaluate codesource...");
                ProgradePolicyDebugger.log("      Policy codesource: " + codeSource.toString());
                ProgradePolicyDebugger.log("      Active codesource: " + pd.getCodeSource().toString());
            }
            if (!codeSource.implies(pd.getCodeSource())) {
                if (debug) {
                    ProgradePolicyDebugger.log("Evaluation (codesource) failed.");
                }
                return false;
            }
        }

        // principals
        if (!principals.isEmpty()) {
            if (debug) {
                ProgradePolicyDebugger.log("Evaluate principals...");
            }
            Principal[] pdPrincipals = pd.getPrincipals();
            if (pdPrincipals == null || pdPrincipals.length == 0) {
                if (debug) {
                    ProgradePolicyDebugger.log("Evaluation (principals) failed. There is no active principals.");
                }
                return false;
            }
            if (debug) {
                ProgradePolicyDebugger.log("Policy principals:");
                for (ProgradePrincipal principal : principals) {
                    ProgradePolicyDebugger.log("      " + principal.toString());
                }
                ProgradePolicyDebugger.log("Active principals:");
                if (pdPrincipals.length == 0) {
                    ProgradePolicyDebugger.log("      none");
                }
                for (int i = 0; i < pdPrincipals.length; i++) {
                    Principal principal = pdPrincipals[i];
                    ProgradePolicyDebugger.log("      " + principal.toString());
                }
            }

            for (ProgradePrincipal principal : principals) {
                boolean contain = false;
                for (int i = 0; i < pdPrincipals.length; i++) {
                    if (principal.hasWildcardClassName()) {
                        contain = true;
                        break;
                    }
                    Principal pdPrincipal = pdPrincipals[i];
                    if (pdPrincipal.getClass().getName().equals(principal.getClassName())) {
                        if (principal.hasWildcardPrincipal()) {
                            contain = true;
                            break;
                        }
                        if (pdPrincipal.getName().equals(principal.getPrincipalName())) {
                            contain = true;
                            break;
                        }
                    }
                }
                if (!contain) {
                    if (debug) {
                        ProgradePolicyDebugger.log("Evaluation (principals) failed.");
                    }
                    return false;
                }
            }
        }

        // permissions
        if (debug) {
            ProgradePolicyDebugger.log("Evaluation codesource/principals passed.");
            String grantOrDeny = (grant) ? "granting" : "denying";
            Enumeration<Permission> elements = permissions.elements();
            while (elements.hasMoreElements()) {
                Permission nextElement = elements.nextElement();
                ProgradePolicyDebugger.log("      " + grantOrDeny + " " + nextElement.toString());
            }
        }

        boolean toReturn = permissions.implies(permission);
        if (debug) {
            if (toReturn) {
                ProgradePolicyDebugger.log("Needed permission found in this entry.");
            } else {
                ProgradePolicyDebugger.log("Needed permission wasn't found in this entry.");
            }
        }
        return toReturn;
    }
}
