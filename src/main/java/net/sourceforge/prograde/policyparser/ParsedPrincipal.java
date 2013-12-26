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
package net.sourceforge.prograde.policyparser;

/**
 *
 * @author Ondrej Lukas
 */
public class ParsedPrincipal {
    
    private String principalClass="";
    private String principalName="";
    private String alias="";
    private boolean classWildcard = false;
    private boolean nameWildcard = false;
    private boolean isAlias = false;

    public ParsedPrincipal(String alias) {
        this.alias=alias;
        isAlias=true;
    }   
    
    public ParsedPrincipal(String principalClass, String principalName) {
        if (principalClass!=null) {
            this.principalClass=principalClass;
        } else {
            classWildcard=true;
        }
        if (principalName!=null) {
            this.principalName=principalName;
        } else {
            nameWildcard=true;
        }
    }           
    
    public String getPrincipalClass() {
        return principalClass;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public String getAlias() {
        return alias;
    }
    
    public boolean hasAlias() {
        return isAlias;
    }

    public boolean hasClassWildcard() {
        return classWildcard;
    }

    public boolean hasNameWildcard() {
        return nameWildcard;
    }    
    
    @Override
    public String toString() {
        String toReturn="";
        String toReturnClass = (classWildcard)? "*" : principalClass;
        String toReturnName = (nameWildcard)? "*" : principalName;
        if (isAlias) {
            toReturn+="\"" + alias + "\"";
        } else {
            toReturn+=toReturnClass + "/" + toReturnName;
        }        
        return toReturn;
    }
    
}
