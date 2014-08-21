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

import java.security.Permission;
import java.security.ProtectionDomain;

/**
 * Interface which is used by {@link NotifyAndAllowPolicy} to send information about denied permission and policy refresh event.
 * 
 * @author Josef Cacek
 */
public interface DeniedPermissionListener {

    /**
     * Called when policy doesn't imply permission.
     * 
     * @param pd
     * @param perm
     */
    void permissionDenied(ProtectionDomain pd, Permission perm);

    /**
     * Called after the policy was refreshed.
     */
    void policyRefreshed();

}
