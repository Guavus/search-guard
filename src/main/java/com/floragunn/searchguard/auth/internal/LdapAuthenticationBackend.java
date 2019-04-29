/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.auth.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.auth.AuthenticationBackend;
import com.floragunn.searchguard.configuration.ConfigurationRepository;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.user.AuthCredentials;
import com.floragunn.searchguard.user.User;

import javax.naming.*;
import javax.naming.directory.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LdapAuthenticationBackend implements AuthenticationBackend {

    private final Settings settings;
    private final Logger log = LogManager.getLogger(this.getClass());
    private final String USERNAME_ATTRIBUTE_DEFAULT = "DN";

    public LdapAuthenticationBackend(final Settings settings, java.nio.file.Path configPath) {
        super();
        this.settings = settings;
    }

    @Override
    public boolean exists(User user) {
        log.debug("In LDAP Authentication, checking if user: " + user.getName() + " exists");
        final Settings cfg = settings;
        if (cfg == null) {
            return false;
        }
       
        String userBindDn = settings.get("bind_dn");
        String userBaseDnTemplate = settings.get("userbase");
        String providerUrl = settings.getAsList("hosts").get(0);
        String searchStr = settings.get("usersearch");
        String bindPasswd = settings.get("password");
        //String username_attribute = settings.get("username_attribute", USERNAME_ATTRIBUTE_DEFAULT);
        log.debug("Config: userbase = " + userBaseDnTemplate + " , host = " + providerUrl + " , usersearch = " + searchStr);

        String userBaseDn = userBaseDnTemplate.replaceAll("\\{0\\}", user.getName());
        String userSearchFilterDn = searchStr.replaceAll("\\{0\\}", user.getName());

        Properties props = new Properties();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, providerUrl);
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        props.put(Context.SECURITY_PRINCIPAL, userBindDn);
        props.put(Context.SECURITY_CREDENTIALS, bindPasswd);
        DirContext ctx = null;

        try {
            
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }
            ctx = AccessController.doPrivileged(new PrivilegedAction<DirContext>() {
                public DirContext run() {
                   
                    DirContext ctx1 = null;
                    NamingEnumeration<SearchResult> results = null;
                    try {
                        ctx1 = new InitialDirContext(props);
                        SearchControls controls = new SearchControls();
                        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                        results = ctx1.search(userBaseDn, userSearchFilterDn, controls);
                        if (results.hasMore()) {
                            log.debug("Found user name in LDAP directory");
                        } else {
                            log.error("User not found in LDAP directory");
                            throw new ElasticsearchSecurityException(user.getName() + " not found");
                        }
                        return ctx1;
                        
                    } catch (Exception e) {
                        log.error("Error in creating context: " + e.getMessage());
                        throw new ElasticsearchSecurityException(user.getName() + " not found");
                    }
                }

            });
        } catch (Exception e) {
            log.error("Error in querying ldap : " + e.getMessage());
            throw new ElasticsearchSecurityException(user.getName() + " not found");
        }
        finally {
            try { ctx.close(); } catch(Exception ex) { }
        }
        return true;        
    }
    
    @Override
    public User authenticate(final AuthCredentials credentials) {
        log.debug("In LDAP Authentication, authenticating user: " + credentials.getUsername());
        Settings cfg = settings;
        if (cfg == null) {
            throw new ElasticsearchSecurityException("Settings null. May be Search Guard is not initialized. See http://docs.search-guard.com/v6/sgadmin");

        }

        String userBindDn = settings.get("bind_dn");
        String userBaseDnTemplate = settings.get("userbase");
        String providerUrl = settings.getAsList("hosts").get(0);
        String searchStr = settings.get("usersearch");
        String bindPasswd = settings.get("password");
        //String username_attribute = settings.get("username_attribute", USERNAME_ATTRIBUTE_DEFAULT);
        log.debug("Config: userbase = " + userBaseDnTemplate + " , host = " + providerUrl + " , usersearch = " + searchStr);

        String userBaseDn = userBaseDnTemplate.replaceAll("\\{0\\}", credentials.getUsername());
        String userSearchFilterDn = searchStr.replaceAll("\\{0\\}", credentials.getUsername());

        Properties props = new Properties();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, providerUrl);
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        props.put(Context.SECURITY_PRINCIPAL, userBindDn);
        props.put(Context.SECURITY_CREDENTIALS, bindPasswd);
        
        if(credentials.getPassword() == null || credentials.getPassword().length == 0) {
            throw new ElasticsearchSecurityException("empty passwords not supported");
        }
        
        String userPasswd = new String(credentials.getPassword(), StandardCharsets.UTF_8);
        DirContext ctx = null;

        try {
            
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                sm.checkPermission(new SpecialPermission());
            }
            ctx = AccessController.doPrivileged(new PrivilegedAction<DirContext>() {
                public DirContext run() {
                   
                    DirContext ctx1 = null;
                    NamingEnumeration<SearchResult> results = null;
                    try {
                        ctx1 = new InitialDirContext(props);
                        SearchControls controls = new SearchControls();
                        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                        results = ctx1.search(userBaseDn, userSearchFilterDn, controls);
                        String userDnVal = null;
                        if (results.hasMore()) {
                            log.debug("Found user name in LDAP directory");
                            SearchResult searchResult = (SearchResult) results.next();
                            userDnVal= searchResult.getNameInNamespace();
                        } else {
                            log.error("User not found in LDAP directory");
                            throw new ElasticsearchSecurityException(credentials.getUsername() + " not found");
                        }

                        // Checking user passwd
                        Properties props1 = new Properties();
                        props1.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                        props1.put(Context.PROVIDER_URL, providerUrl);
                        props1.put(Context.SECURITY_AUTHENTICATION, "simple");
                        props1.put(Context.SECURITY_PRINCIPAL, userDnVal);
                        props1.put(Context.SECURITY_CREDENTIALS, userPasswd);
                        ctx1 = new InitialDirContext(props1);
                        return ctx1;
                        
                    } catch (Exception e) {
                        log.error("Error in creating context: " + e.getMessage());
                        throw new ElasticsearchSecurityException(credentials.getUsername() + " not found");
                    }
                }

            });
        } catch (Exception e) {
            log.error("Error in querying ldap : " + e.getMessage());
            throw new ElasticsearchSecurityException(credentials.getUsername() + " not found");
        }
        finally {
            try { 
                //results.close(); 
            ctx.close(); } catch(Exception ex) { }
        }
        log.debug("ldap auth succeeded for user: " + credentials.getUsername());
        AuthCredentials creds = new AuthCredentials(credentials.getUsername(), credentials.getPassword());
        return new User(credentials.getUsername(), null, creds);
    }

    @Override
    public String getType() {
        return "ldap";
    }

    /*
    public static void main(String args[]) {
        List<String> hosts = new ArrayList<String>();
        hosts.add("ldap://192.168.154.190:389");
        //Settings sts = Settings.builder().put("userbase", "cn={0},dc=example,dc=local")
        //                .putList("hosts", hosts).build();
        Settings sts = Settings.builder().put("userbase", "uid={0},ou=People,dc=example,dc=local")
                .putList("hosts", hosts).build();

        LdapAuthenticationBackend lab = new LdapAuthenticationBackend(sts, null);
        try {
        AuthCredentials creds = new AuthCredentials("guest", "guest123".getBytes("UTF-8"));
        creds.addAttribute("password", "guest123");
        User user = new User("guest", null, creds);
        boolean ret = lab.exists(user);
        System.out.println("User check returned: " + ret);
        } catch (Exception e) {
            e.printStackTrace();
        }
                       
    }
    */
}
