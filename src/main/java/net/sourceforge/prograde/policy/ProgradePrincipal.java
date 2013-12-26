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

/**
 *
 * @author Ondrej Lukas
 */
public class ProgradePrincipal {
    
    private String className;
    private String principalName;
    private boolean wildcardClassName;
    private boolean wildcardPrincipal;

    public ProgradePrincipal() {
    }    

    public ProgradePrincipal(String className, String principalName, boolean wildcardClassName, boolean wildcardPrincipal) {
        this.className = className;
        this.principalName = principalName;
        this.wildcardClassName = wildcardClassName;
        this.wildcardPrincipal = wildcardPrincipal;
    }   
    
    public String getClassName() {
        return className;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public boolean hasWildcardClassName() {
        return wildcardClassName;
    }

    public boolean hasWildcardPrincipal() {
        return wildcardPrincipal;
    }

    public void setClassName(String type) {
        this.className = type;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public void setWildcardClassName(boolean wildcardType) {
        this.wildcardClassName = wildcardType;
    }

    public void setWildcardPrincipal(boolean wildcardPrincipal) {
        this.wildcardPrincipal = wildcardPrincipal;
    }
    
    @Override
    public String toString() {
        String toReturn="";
        String toReturnClass = (wildcardClassName)? "*" : className;
        String toReturnName = (wildcardPrincipal)? "*" : principalName;
        toReturn+=toReturnClass + "/" + toReturnName;              
        return toReturn;
    }
    
}
