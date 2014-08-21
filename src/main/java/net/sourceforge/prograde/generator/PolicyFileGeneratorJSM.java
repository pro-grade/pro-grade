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

/**
 * Class extending SecurityManager and using {@link NotifyAndAllowPolicy} policy with
 * {@link GeneratePolicyFromDeniedPermissions} listener for generating policy file from denied permissions.
 * 
 * @author Josef Cacek
 */
public class PolicyFileGeneratorJSM extends SecurityManager {

    /**
     * JSM Constructor.
     */
    public PolicyFileGeneratorJSM() {
        SecurityActions.setPolicy(new NotifyAndAllowPolicy(null, new GeneratePolicyFromDeniedPermissions()));
    }
}
