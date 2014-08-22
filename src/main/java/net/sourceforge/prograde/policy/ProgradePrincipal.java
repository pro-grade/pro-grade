package net.sourceforge.prograde.policy;

/**
 * Class representing parsed principal which is used in ProgradePolicyEntry.
 * 
 * @author Ondrej Lukas
 */
public class ProgradePrincipal {

    private String className;
    private String principalName;
    private boolean wildcardClassName;
    private boolean wildcardPrincipal;

    /**
     * Nonparametric constructor of ProgradePrincipal.
     */
    public ProgradePrincipal() {
    }

    /**
     * Constructor of ProgradePrincipal.
     * 
     * @param className name of Principal class
     * @param principalName name of Principal
     * @param wildcardClassName true if principal entry has wildcard for principal class name or false if it doesn't have it
     * @param wildcardPrincipal true if principal entry has wildcard for principal name or false if it doesn't have it
     */
    public ProgradePrincipal(String className, String principalName, boolean wildcardClassName, boolean wildcardPrincipal) {
        this.className = className;
        this.principalName = principalName;
        this.wildcardClassName = wildcardClassName;
        this.wildcardPrincipal = wildcardPrincipal;
    }

    /**
     * Getter of Principal class name.
     * 
     * @return name of Principal class
     */
    public String getClassName() {
        return className;
    }

    /**
     * Getter of Principal name.
     * 
     * @return name of Principal
     */
    public String getPrincipalName() {
        return principalName;
    }

    /**
     * Method for determining whether principal has wildcard for class name.
     * 
     * @return true if principal has wildcard for class name or false if it doesn't have it
     */
    public boolean hasWildcardClassName() {
        return wildcardClassName;
    }

    /**
     * Method for determining whether principal has wildcard for principal name.
     * 
     * @return true if principal has wildcard for principal name or false if it doesn't have it
     */
    public boolean hasWildcardPrincipal() {
        return wildcardPrincipal;
    }

    /**
     * Setter of Principal class name.
     * 
     * @param type name of Principal class
     */
    public void setClassName(String type) {
        this.className = type;
    }

    /**
     * Setter of Principal name.
     * 
     * @param principalName name of Principal
     */
    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    /**
     * Setter of principal class name wildcard.
     * 
     * @param wildcardType true if principal has wildcard for class name or false if it doesn't have it
     */
    public void setWildcardClassName(boolean wildcardType) {
        this.wildcardClassName = wildcardType;
    }

    /**
     * Setter of principal name wildcard.
     * 
     * @param wildcardPrincipal true if principal has wildcard for principal name or false if it doesn't have it
     */
    public void setWildcardPrincipal(boolean wildcardPrincipal) {
        this.wildcardPrincipal = wildcardPrincipal;
    }

    @Override
    public String toString() {
        String toReturn = "";
        String toReturnClass = (wildcardClassName) ? "*" : className;
        String toReturnName = (wildcardPrincipal) ? "*" : principalName;
        toReturn += toReturnClass + "/" + toReturnName;
        return toReturn;
    }
}
