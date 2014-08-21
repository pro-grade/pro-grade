/* Copyright 2014 Josef Cacek
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
 */
package net.sourceforge.prograde.generator;

import java.io.PrintStream;
import java.security.Permission;
import java.security.ProtectionDomain;

/**
 * Simple implementation of {@link DeniedPermissionListener} which prints the denied permissions to given {@link PrintStream}
 * (or {@link System#err} when no {@link PrintStream} instance is provided).
 */
public final class PrintDeniedPermissions implements DeniedPermissionListener {

    private final PrintStream printStream;

    /**
     * Constructor with default {@link PrintStream} ({@link System#err}).
     */
    public PrintDeniedPermissions() {
        this(null);
    }

    /**
     * Constructor, which initializes printing to given {@link PrintStream} instance.
     * 
     * @param printStream may be null (may be null)
     */
    public PrintDeniedPermissions(final PrintStream printStream) {
        this.printStream = (printStream == null ? System.err : printStream);
    }

    /*
     * (non-Javadoc)
     * 
     * @see net.sourceforge.prograde.generator.DeniedPermissionListener#permissionDenied(java.security.Permission,
     * java.security.ProtectionDomain)
     */
    public void permissionDenied(ProtectionDomain pd, Permission perm) {
        printStream.println(">> Denied permission " + perm.getClass() + " " + perm.getName() + " " + perm.getActions());
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
