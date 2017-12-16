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

import java.io.PrintStream;
import java.security.Permission;
import java.security.ProtectionDomain;
import static net.sourceforge.prograde.generator.GeneratorUtils.createPrintablePermissionName;

/**
 * Simple implementation of {@link DeniedPermissionListener} which prints the denied permissions to given {@link PrintStream}
 * (or {@link System#err} when no {@link PrintStream} instance is provided).
 */
public final class PrintDeniedPermissions implements DeniedPermissionListener {

    private final PrintStream printStream;
    private final boolean includeCodeSource;

    /**
     * Constructor with default {@link PrintStream} ({@link System#err}).
     */
    public PrintDeniedPermissions() {
        this(null, true);
    }

    /**
     * Constructor, which initializes printing to given {@link PrintStream} instance.
     * 
     * @param printStream may be null (may be null)
     */
    public PrintDeniedPermissions(final PrintStream printStream, final boolean includeCodeSource) {
        this.printStream = (printStream == null ? System.err : printStream);
        this.includeCodeSource = includeCodeSource;
    }

    /*
     * (non-Javadoc)
     * 
     * @see net.sourceforge.prograde.generator.DeniedPermissionListener#permissionDenied(java.security.Permission,
     * java.security.ProtectionDomain)
     */
    public void permissionDenied(final ProtectionDomain pd, final Permission perm) {
        final StringBuilder sb = new StringBuilder(">> Denied permission ");
        sb.append(perm.getClass().getName()).append(" \"") //
                .append(createPrintablePermissionName(perm.getName())).append("\""); //
        if (perm.getActions()!=null && !perm.getActions().equals("")) {
                sb.append(", \"").append(perm.getActions()).append("\"");
        }
        sb.append(";");
        if (includeCodeSource) {
            sb.append("\n>>> CodeSource: " + pd.getCodeSource());
        }
        printStream.println(sb);
    }

    /*
     * (non-Javadoc)
     * 
     * @see net.sourceforge.prograde.generator.DeniedPermissionListener#policyReloaded()
     */
    public void policyRefreshed() {
        printStream.println(">> Policy was refreshed.");
    }

}
