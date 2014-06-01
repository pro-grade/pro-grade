/** 
 * Copyright 2014 Josef Cacek
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

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Policy wrapper for debug purposes. It's main goal is to generate policy file with permissions checked by application, but not
 * included in the wrapped policy.
 * 
 * @author Josef Cacek
 */
public class PolicyGenerator extends Policy {

    private final Map<CodeSource, Set<Permission>> missingPermissions = new HashMap<CodeSource, Set<Permission>>();
    private File file;

    private Policy wrappedPolicy;

    public PolicyGenerator() {
        this(null, null);
    }

    public PolicyGenerator(File targetFile, Policy policy) {
        if (targetFile != null) {
            file = targetFile;
        } else {
            String sysProp = SecurityActions.getSystemProperty("prograde.generated.policy");
            if (sysProp != null) {
                file = new File(sysProp);
            } else {
                try {
                    file = File.createTempFile("generated-", ".policy");
                } catch (IOException e) {
                    throw new RuntimeException("Unable to create a new policy file", e);
                }
            }
            try {
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        wrappedPolicy = policy != null ? policy : SecurityActions.getPolicy();
    }

    @Override
    public boolean implies(ProtectionDomain protectionDomain, Permission permission) {
        if (wrappedPolicy != null && permission.getClass() == AllPermission.class) {
            return wrappedPolicy.implies(protectionDomain, permission);
        }
        if (wrappedPolicy == null || !wrappedPolicy.implies(protectionDomain, permission)) {
            final CodeSource codeSource = protectionDomain.getCodeSource();
            Set<Permission> permSet = missingPermissions.get(codeSource);
            if (permSet == null) {
                permSet = new HashSet<Permission>();
                missingPermissions.put(codeSource, permSet);
            }
            if (permSet.add(permission)) {
                writeToFile();
            }
        }
        return true;
    }

    @Override
    public void refresh() {
        if (wrappedPolicy != null)
            wrappedPolicy.refresh();
        missingPermissions.clear();
        writeToFile();
    }

    private void writeToFile() {
        PrintWriter pw = null;
        try {
            pw = new PrintWriter(file, "UTF-8");
            pw.println("// PolicyGenerator - timestamp: " + new Date().toString());
            pw.println();
            for (Map.Entry<CodeSource, Set<Permission>> csEntry : missingPermissions.entrySet()) {
                pw.println("grant codeBase \"" + csEntry.getKey().getLocation() + "\" {");
                for (Permission p : csEntry.getValue()) {
                    pw.print("  permission " + p.getClass().getName());
                    if (p.getName() != null) {
                        pw.print(" \"" + p.getName() + "\"");
                    }
                    if (p.getActions() != null) {
                        pw.print(", \"" + p.getActions() + "\"");
                    }
                    pw.println(";");
                }
                pw.println("};");
                pw.println();
            }
            pw.println("// PolicyGenerator - That's all");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (pw != null) {
                try {
                    pw.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
