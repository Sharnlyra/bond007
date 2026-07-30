Your File:InformaticaRepository.java
package com.helpsystems.enterprise.core.busobj.informatica;
 
 
 
import org.apache.log4j.*;
 
import com.helpsystems.common.core.access.*;
import com.helpsystems.common.core.busobj.*;
import com.helpsystems.enterprise.core.scheduler.*;
import com.helpsystems.enterprise.core.util.*;
 
/**
 * <p>
 * Copyright (c) 2012 Help/Systems, Inc.
 * </p>
 * @author mmirzoya created on Nov 9, 2012
 * @version 1.0
 */
public class InformaticaRepository extends AbstractBusinessObject implements
        BasicIdentifier {
 
    private static final long serialVersionUID = 5825077097049477945L;
    // instance fields
    private long OID;
    private String systemName;
    private int port = 7333;
    private String domain;
    private String repoName;
    private String infaUserName;
    private String securityDomain;
    private String passwordSalt;
    private String encryptedPassword;
    private boolean useHTTPS = false;
    
    
    
    private static String HTTP_PROTOCOL = "http";
    private static String HTTPS_PROTOCOL = "https";
    private static String COLON = ":";
    private static String REPO_META_DATA = "/wsh/services/BatchServices/Metadata";
    private static String DOUBLE_SLASH = "//";
    private static String DI_META_DATA = "/wsh/services/BatchServices/DataIntegration";
    
 
    /** The LOGGER for this class. */
    private static final Logger LOGGER = Logger
            .getLogger(InformaticaRepository.class);
 
    /**
     * Default empty constructor.
     */
    public InformaticaRepository() {
        // keep empty
    }
    /**
     * @return the oID
     */
    public long getOID() {
        return OID;
    }
 
    /**
     * @param oID the oID to set
     */
    public void setOID(final long oID) {
        this.OID = oID;
    }
 
    /**
     * @return the systemName
     */
    public String getSystemName() {
        return systemName;
    }
 
    /**
     * @param systemName the systemName to set
     */
    public void setSystemName(final String systemName) {
        this.systemName = systemName;
    }
 
    /**
     * @return the port
     */
    public int getPort() {
        return port;
    }
 
    /**
     * @param port the port to set
     */
    public void setPort(final int port) {
        this.port = port;
    }
 
    /**
     * @return the domain
     */
    public String getDomain() {
        return domain;
    }
 
    /**
     * @param domain the domain to set
     */
    public void setDomain(final String domain) {
        this.domain = domain;
    }
 
    /**
     * @return the repoName
     */
    public String getRepoName() {
        return repoName;
    }
 
    /**
     * @param repoName the repoName to set
     */
    public void setRepoName(final String repoName) {
        this.repoName = repoName;
    }
 
    /**
     * @return the infaUser
     */
    public String getInfaUserName() {
        return infaUserName;
    }
 
    /**
     * @param infaUser the infaUser to set
     */
    public void setInfaUserName(final String infaUserName) {
        this.infaUserName = infaUserName;
    }
 
    /**
     * @return the securityDomain
     */
    public String getSecurityDomain() {
        return securityDomain;
    }
 
    /**
     * @param securityDomain the securityDomain to set
     */
    public void setSecurityDomain(final String securityDomain) {
        this.securityDomain = securityDomain;
    }
 
    /**
     * @return the passwordSalt
     */
    public String getPasswordSalt() {
        return passwordSalt;
    }
 
    /**
     * @param passwordSalt the passwordSalt to set
     */
    public void setPasswordSalt(final String passwordSalt) {
        this.passwordSalt = passwordSalt;
    }
 
    /**
     * @return the encryptedPassword
     */
    public String getEncryptedPassword() {
        return encryptedPassword;
    }
 
    /**
     * @param encryptedPassword the encryptedPassword to set
     */
    public void setEncryptedPassword(final String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }
 
   
    /**
     * @return
     */
    public String getRepoWSHUrl() {
        
        final StringBuilder whsURL = new StringBuilder();
        
        if(useHTTPS){
            whsURL.append(HTTPS_PROTOCOL);
        }else{
            whsURL.append(HTTP_PROTOCOL);
        }
        
        whsURL.append(COLON);
        whsURL.append(DOUBLE_SLASH);
        whsURL.append(this.systemName);
        whsURL.append(COLON);
        whsURL.append(this.port);
        whsURL.append(REPO_META_DATA);
        
        return whsURL.toString();
    }
    
    /**
     * @return
     */
    public String getDIWSHUrl() {
        
        final StringBuilder whsURL = new StringBuilder();
        
        if(useHTTPS){
            whsURL.append(HTTPS_PROTOCOL);
        }else{
            whsURL.append(HTTP_PROTOCOL);
        }
        
        whsURL.append(COLON);
        whsURL.append(DOUBLE_SLASH);
        whsURL.append(this.systemName);
        whsURL.append(COLON);
        whsURL.append(this.port);
        whsURL.append(DI_META_DATA);
        
        return whsURL.toString();
    }
 
    /**
     * @return
     * @throws ResourceUnavailableException
     */
    public String getDecryptedPassword(){
 
        String passwordWithSalt = null;
        try {
            passwordWithSalt = UnacodeMash
                    .unMash(getEncryptedPassword());
            passwordWithSalt = passwordWithSalt.replaceAll(getPasswordSalt(), "");
        } catch (ResourceUnavailableException e) {
            LOGGER.error("An error occurred while decrypting a password.", e);
        }
 
        return passwordWithSalt;
    }
    
    /**
     * @return the useHTTPS
     */
    public boolean isUseHTTPS() {
        return useHTTPS;
    }
    /**
     * @param useHTTPS the useHTTPS to set
     */
    public void setUseHTTPS(boolean useHTTPS) {
        this.useHTTPS = useHTTPS;
    }
    
    @Override
    public String toString() {
        final StringBuilder repoAsString = new StringBuilder();
        
        repoAsString.append(super.toString());
        repoAsString.append("Name = ");
        repoAsString.append(super.getName());
        repoAsString.append("Description = ");
        repoAsString.append(super.getDescription());
        repoAsString.append("SystemName = ");
        repoAsString.append(this.systemName);
        repoAsString.append("port = ");
        repoAsString.append(this.port);
        repoAsString.append("domain = ");
        repoAsString.append(this.domain);
        repoAsString.append("repoName = ");
        repoAsString.append(this.repoName);
        repoAsString.append("InfaUserName = ");
        repoAsString.append(this.infaUserName);
        repoAsString.append("SecurityDomain = ");
        repoAsString.append(this.securityDomain);
        repoAsString.append("EncryptedPassword = ");
        repoAsString.append(this.encryptedPassword);
        repoAsString.append("PasswrdSalt = ");
        repoAsString.append(this.passwordSalt);
        repoAsString.append("SystemName = ");
 
        return repoAsString.toString();
 
    }
   
 
}
