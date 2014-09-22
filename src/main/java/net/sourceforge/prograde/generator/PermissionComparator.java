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

import java.security.Permission;
import java.util.Comparator;

/**
 * Simple Comparator class for sorting Permission alphabetically. It returns compared names of Permission classes. If they are
 * same it returns compared names of permission. If they are same it returns compared permissions actions.
 *
 * @author olukas
 */
public class PermissionComparator implements Comparator<Permission> {

    @Override
    public int compare(Permission p1, Permission p2) {
        final int compareClassNames = p1.getClass().getName().compareTo(p2.getClass().getName());
        if (compareClassNames != 0) {
            return compareClassNames;
        } else {
            final int comparePermissionNames = p1.getName().compareTo(p2.getName());
            if (comparePermissionNames != 0) {
                return comparePermissionNames;
            } else {
                return p1.getActions().compareTo(p2.getActions());
            }
        }
    }

}
