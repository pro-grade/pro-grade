/*
 * #%L
 * pro-grade
 * %%
 * Copyright (C) 2013 - 2017 Ondřej Lukáš, Josef Cacek
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

/**
 * Util class for generating permissions.
 *
 * @author olukas
 */
final class GeneratorUtils {

    private GeneratorUtils() {
    }
    
    /**
     * Method which transform permission name to the name which can be correctly used in policy file.
     * 
     * @param permissionName original permission name for transforming, cannot be null
     * @return name of permission which can be correctly used in policy file
     */
    static String createPrintablePermissionName(String permissionName) {
        return permissionName.replace("\"", "\\\"");
    }
}
