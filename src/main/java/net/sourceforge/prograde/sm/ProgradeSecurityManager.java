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
package net.sourceforge.prograde.sm;

import java.security.AccessController;
import java.security.Policy;
import java.security.PrivilegedAction;

import net.sourceforge.prograde.policy.ProgradePolicyFile;

/**
 * Class extending SecurityManager and using ProgradePolicyFile for access controlling.
 * 
 * @author Ondrej Lukas
 */
public class ProgradeSecurityManager extends SecurityManager {

    /**
     * Constructor which also set ProgradePolicyFile as Policy.
     */
    public ProgradeSecurityManager() {
        super();
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                Policy.setPolicy(new ProgradePolicyFile());
                return null;
            }
        });
    }
}
