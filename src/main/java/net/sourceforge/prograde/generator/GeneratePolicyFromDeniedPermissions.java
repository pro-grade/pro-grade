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
package net.sourceforge.prograde.generator;

import java.io.File;
import java.io.FilePermission;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * DeniedPermissionListener implementation which generates a policy file with the denied permissions.
 * <p>
 * File to which is the policy written is either provided to a constructor or value of system property
 * {@value #PROGRADE_GENERATED_POLICY} is used as the file path. When neither a file instance nor the system property is
 * provided a temporary file is created using {@link File#createTempFile(String, String)}.
 * 
 * @author Josef Cacek
 */
public final class GeneratePolicyFromDeniedPermissions implements DeniedPermissionListener {

    /**
     * System property name for setting generated policy file path when the file is not specified in the constructor.
     */
    public static final String PROGRADE_GENERATED_POLICY = "prograde.generated.policy";

    private final PrivilegedAction<Void> WRITE_TO_FILE_ACTION = new PrivilegedAction<Void>() {
        @Override
        public Void run() {
            writeToFile();
            return null;
        }
    };

    private final Map<CodeSource, Set<Permission>> missingPermissions = Collections
            .synchronizedMap(new TreeMap<CodeSource, Set<Permission>>(new CodesourceComparator()));
    private final File file;
    private boolean refreshed = false;
    private final FilePermission filePermissionToSkip;

    /**
     * Default constructor.
     */
    public GeneratePolicyFromDeniedPermissions() {
        this(null);
    }

    /**
     * Constructor.
     * 
     * @param targetFile file to which the policy generated from denied permissions will be written
     */
    public GeneratePolicyFromDeniedPermissions(final File targetFile) {
        if (targetFile != null) {
            file = targetFile;
        } else {
            String sysProp = SecurityActions.getSystemProperty(PROGRADE_GENERATED_POLICY);
            if (sysProp != null) {
                file = new File(sysProp);
            } else {
                try {
                    file = File.createTempFile("generated-", ".policy");
                    System.err.println("Writing policy to temporary file: " + file.getAbsolutePath());
                } catch (IOException e) {
                    throw new RuntimeException("Unable to create a new policy file", e);
                }
            }
        }
        filePermissionToSkip = new FilePermission(file.getPath(), "write");
    }

    /**
     * Writes the given permission under the grant entry with codesource from given {@link ProtectionDomain} into the generated
     * policy file.
     * 
     * @see net.sourceforge.prograde.generator.DeniedPermissionListener#permissionDenied(java.security.ProtectionDomain,
     *      java.security.Permission)
     */
    @Override
    public void permissionDenied(final ProtectionDomain pd, final Permission perm) {
        if (filePermissionToSkip.equals(perm)) {
            return;
        }
        final CodeSource codeSource = pd.getCodeSource();
        Set<Permission> permSet = missingPermissions.get(codeSource);
        if (permSet == null) {
            synchronized (missingPermissions) {
                permSet = missingPermissions.get(codeSource);
                if (permSet == null) {
                    permSet = Collections.synchronizedSet(new TreeSet<Permission>(new PermissionComparator()));
                    missingPermissions.put(codeSource, permSet);
                }
            }
        }
        if (permSet.add(perm)) {
            AccessController.doPrivileged(WRITE_TO_FILE_ACTION);
        }
    }

    /**
     * Clears generated policy file.
     * 
     * @see net.sourceforge.prograde.generator.DeniedPermissionListener#policyRefreshed()
     */
    @Override
    public void policyRefreshed() {
        synchronized (missingPermissions) {
            refreshed = true;
        }
        AccessController.doPrivileged(WRITE_TO_FILE_ACTION);
    }

    private void writeToFile() {
        PrintWriter pw = null;
        final String className = getClass().getSimpleName();
        synchronized (missingPermissions) {
            try {
                pw = new PrintWriter(file, "UTF-8");
                pw.println("// " + className + " - timestamp: " + new Date().toString());
                if (refreshed) {
                    pw.println("// The policy was refreshed already.");
                }
                pw.println();
                for (Map.Entry<CodeSource, Set<Permission>> csEntry : missingPermissions.entrySet()) {
                    pw.println("grant codeBase \"" + csEntry.getKey().getLocation() + "\" {");
                    for (Permission p : csEntry.getValue()) {
                        pw.print("  permission " + p.getClass().getName());
                        if (p.getName() != null) {
                            pw.print(" \"" + p.getName() + "\"");
                        }
                        if (p.getActions() != null && !p.getActions().equals("")) {
                            pw.print(", \"" + p.getActions() + "\"");
                        }
                        pw.println(";");
                    }
                    pw.println("};");
                    pw.println();
                }
                pw.println("// " + className + " - That's all");
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
    
}
