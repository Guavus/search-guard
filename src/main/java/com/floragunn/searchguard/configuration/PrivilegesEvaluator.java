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

package com.floragunn.searchguard.configuration;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;

import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.apache.hadoop.security.UserGroupInformation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.RealtimeRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesAction;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.elasticsearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexAction;
import org.elasticsearch.action.bulk.BulkAction;
import org.elasticsearch.action.bulk.BulkItemRequest;
import org.elasticsearch.action.bulk.BulkShardRequest;
import org.elasticsearch.action.delete.DeleteAction;
import org.elasticsearch.action.get.MultiGetAction;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.search.MultiSearchAction;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchScrollAction;
import org.elasticsearch.action.termvectors.MultiTermVectorsAction;
import org.elasticsearch.action.update.UpdateAction;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.IndexMetaData;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.query.MatchNoneQueryBuilder;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.TermsQueryBuilder;
import org.elasticsearch.index.reindex.ReindexAction;
import org.elasticsearch.search.aggregations.AggregationBuilder;
import org.elasticsearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.RemoteClusterAware;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.SpecialPermission;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.resolver.IndexResolverReplacer;
import com.floragunn.searchguard.resolver.IndexResolverReplacer.Resolved;
import com.floragunn.searchguard.sgconf.ConfigModel;
import com.floragunn.searchguard.sgconf.ConfigModel.SgRoles;
import com.floragunn.searchguard.support.SnapshotRestoreHelper;
import com.floragunn.searchguard.http.HTTPSpnegoAuthenticator;
import com.floragunn.searchguard.support.Base64Helper;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.UserGroupMappingCache;
import com.floragunn.searchguard.support.WildcardMatcher;
import com.floragunn.searchguard.user.User;
import com.google.common.base.Strings;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.Sets;
import com.kerb4j.client.SpnegoClient;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import com.floragunn.searchguard.user.VXUser;

import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.authorization.hadoop.config.RangerConfiguration;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import java.net.URLClassLoader;
import java.net.URL;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;

public class PrivilegesEvaluator {


    protected final Logger log = LogManager.getLogger(this.getClass());
    protected final Logger actionTrace = LogManager.getLogger("sg_action_trace");
    private final ClusterService clusterService;
    private final ActionGroupHolder ah;
    private final IndexNameExpressionResolver resolver;
    private final String[] sgDeniedActionPatterns;
    private final AuditLog auditLog;
    private ThreadContext threadContext;
    //private final static IndicesOptions DEFAULT_INDICES_OPTIONS = IndicesOptions.lenientExpandOpen();
    private final ConfigurationRepository configurationRepository;

    private final String searchguardIndex;
    private PrivilegesInterceptor privilegesInterceptor;

    private final boolean enableSnapshotRestorePrivilege;
    private final boolean checkSnapshotRestoreWritePrivileges;
    private ConfigConstants.RolesMappingResolution rolesMappingResolution;

    private final ClusterInfoHolder clusterInfoHolder;
    //private final boolean typeSecurityDisabled = false;
    private final ConfigModel configModel;
    private final IndexResolverReplacer irr;
    
    private static final String[] READ_ACTIONS = new String[]{
            "indices:data/read/msearch",
            "indices:data/read/mget",
            "indices:data/read/get",
            "indices:data/read/search",
            "indices:data/read/field_caps*"
            //"indices:admin/mappings/fields/get*"
            };
    
    private static final QueryBuilder NONE_QUERY = new MatchNoneQueryBuilder();
    public static final String ACCESS_TYPE_READ = "read";
    public static final String ACCESS_TYPE_WRITE = "write";
    public static final String ACCESS_TYPE_ADMIN = "es_admin";
    private static volatile RangerBasePlugin rangerPlugin = null;
    private String rangerUrl = null;
    private UserGroupMappingCache usrGrpCache = null;
    private boolean enabledFlag = false;
    private boolean initUGI = false;

    public PrivilegesEvaluator(final ClusterService clusterService, final ThreadPool threadPool, final ConfigurationRepository configurationRepository, final ActionGroupHolder ah,
            final IndexNameExpressionResolver resolver, AuditLog auditLog, final Settings settings, final PrivilegesInterceptor privilegesInterceptor,
            final ClusterInfoHolder clusterInfoHolder) {

        super();
        this.configurationRepository = configurationRepository;
        this.clusterService = clusterService;
        this.ah = ah;
        this.resolver = resolver;
        this.auditLog = auditLog;

        this.threadContext = threadPool.getThreadContext();
        this.searchguardIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME, ConfigConstants.SG_DEFAULT_CONFIG_INDEX);
        this.privilegesInterceptor = privilegesInterceptor;
        this.enableSnapshotRestorePrivilege = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
                ConfigConstants.SG_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE);
        this.checkSnapshotRestoreWritePrivileges = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
                ConfigConstants.SG_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES);

        try {
            rolesMappingResolution = ConfigConstants.RolesMappingResolution.valueOf(settings.get(ConfigConstants.SEARCHGUARD_ROLES_MAPPING_RESOLUTION, ConfigConstants.RolesMappingResolution.MAPPING_ONLY.toString()).toUpperCase());
        } catch (Exception e) {
            log.error("Cannot apply roles mapping resolution",e);
            rolesMappingResolution =  ConfigConstants.RolesMappingResolution.MAPPING_ONLY;
        }

        final List<String> sgIndexdeniedActionPatternsList = new ArrayList<String>();
        sgIndexdeniedActionPatternsList.add("indices:data/write*");
        sgIndexdeniedActionPatternsList.add("indices:admin/close");
        sgIndexdeniedActionPatternsList.add("indices:admin/delete");
        sgIndexdeniedActionPatternsList.add("cluster:admin/snapshot/restore");
        //deniedActionPatternsList.add("indices:admin/settings/update");
        //deniedActionPatternsList.add("indices:admin/upgrade");

        sgDeniedActionPatterns = sgIndexdeniedActionPatternsList.toArray(new String[0]);
        this.clusterInfoHolder = clusterInfoHolder;
        //this.typeSecurityDisabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_DISABLE_TYPE_SECURITY, false);
        configModel = new ConfigModel(ah, configurationRepository);
        irr = new IndexResolverReplacer(resolver, clusterService, clusterInfoHolder);
        
        //Check if Ranger Authz is enabled
        
        enabledFlag = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_AUTH_RANGER_ENABLED, false);
        String ES_PLUGIN_APP_ID = settings.get(ConfigConstants.SEARCHGUARD_AUTH_RANGER_APP_ID);
        
        if (ES_PLUGIN_APP_ID == null && enabledFlag) {
            throw new ElasticsearchSecurityException("Search Guard Ranger plugin enabled but appId config not valid");
        }
        
        if (!initializeUGI(settings)) {
            log.error("UGI not getting initialized.");
            /*
            if (enabledFlag) {
                throw new ElasticsearchSecurityException("Unable to initialize spnego client and UGI");
            }
            */
        }
        
        if (enabledFlag) {
            configureRangerPlugin(settings);
            usrGrpCache = new UserGroupMappingCache();
            usrGrpCache.init();
        }
    }
    
    public void configureRangerPlugin(Settings settings) {
        String svcType = settings.get(ConfigConstants.SEARCHGUARD_AUTH_RANGER_SERVICE_TYPE, "elasticsearch");
        String appId = settings.get(ConfigConstants.SEARCHGUARD_AUTH_RANGER_APP_ID);
        
        RangerBasePlugin me = rangerPlugin;
        if (me == null) {
            synchronized(PrivilegesEvaluator.class) {
                me = rangerPlugin;
                if (me == null) {
                    me = rangerPlugin = new RangerBasePlugin(svcType, appId);
                }    
            }
        }
        log.debug("Calling ranger plugin init");
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                ClassLoader cl = org.apache.ranger.authorization.hadoop.config.RangerConfiguration.class.getClassLoader();
                URL[] urls = ((URLClassLoader)cl).getURLs();
                String pluginPath = null;
                for(URL url: urls){
                    String urlFile = url.getFile();
                    int idx = urlFile.indexOf("ranger-plugins-common");
                    if (idx != -1) {
                        pluginPath = urlFile.substring(0, idx);
                    }
                }

                try {
                    Method method = URLClassLoader.class.getDeclaredMethod("addURL", new Class[]{URL.class});
                    method.setAccessible(true);
                    String rangerResourcesPath = pluginPath + "resources/";
                    method.invoke(cl, new Object[]{new File(rangerResourcesPath).toURI().toURL()});
                } catch (Exception e) {
                    log.error("Error in adding ranger config files to classpath : " + e.getMessage());
                    if (log.isDebugEnabled()) {
                        e.printStackTrace();
                    }
                }
                rangerPlugin.init();
                return null;
            }
        });
        this.rangerUrl = RangerConfiguration.getInstance().get("ranger.plugin.elasticsearch.policy.rest.url");
        log.debug("Ranger uri : " + rangerUrl);
        RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
        rangerPlugin.setResultProcessor(auditHandler);
    }

    private Settings getRolesSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES, false);
    }

    private Settings getRolesMappingSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_ROLES_MAPPING, false);
    }

    private Settings getConfigSettings() {
        return configurationRepository.getConfiguration(ConfigConstants.CONFIGNAME_CONFIG, false);
    }

    //TODO: optimize, recreate only if changed
    private SgRoles getSgRoles(final User user, final TransportAddress caller) {
        Set<String> roles = mapSgRoles(user, caller);
        return configModel.load().filter(roles);
    }

    public boolean initializeUGI(Settings settings) {
        if (initUGI) {
            return true;
        }
        
        String svcName = settings.get(ConfigConstants.SEARCHGUARD_KERBEROS_ACCEPTOR_PRINCIPAL);        
        String keytabPath = settings.get(ConfigConstants.SEARCHGUARD_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, 
                HTTPSpnegoAuthenticator.SERVER_KEYTAB_PATH);
        String krbConf = settings.get(ConfigConstants.SEARCHGUARD_KERBEROS_KRB5_FILEPATH, 
                HTTPSpnegoAuthenticator.KRB5_CONF);
        
        if (Strings.isNullOrEmpty(svcName)) {
            log.error("Acceptor kerberos principal is empty or null");
            return false;
        }
        
        HTTPSpnegoAuthenticator.initSpnegoClient(svcName, keytabPath, krbConf);
        
        SpnegoClient spnegoClient = HTTPSpnegoAuthenticator.getSpnegoClient();
        
        if (spnegoClient == null) {
            log.error("Spnego client not initialized");
            return false;
        }
        
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }
        
        initUGI = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            public Boolean run() {
                Subject subject = spnegoClient.getSubject();
        
                try {
                    UserGroupInformation ugi = MiscUtil.createUGIFromSubject(subject);
                    if (ugi != null) {
                        MiscUtil.setUGILoginUser(ugi, subject);
                    } else {
                        log.error("Unable to initialize UGI");
                        return false;
                    }
                } catch (Throwable t) {
                    log.error("Exception while trying to initialize UGI: " + t.getMessage());
                    return false;
                }
                return true;
            }
        });

        return initUGI;
    }

    public static class IndexType {

        private String index;
        private String type;

        public IndexType(String index, String type) {
            super();
            this.index = index;
            this.type = type.equals("_all")? "*": type;
        }

        public String getCombinedString() {
            return index+"#"+type;
        }

        public String getIndex() {
            return index;
        }

        public String getType() {
            return type;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((index == null) ? 0 : index.hashCode());
            result = prime * result + ((type == null) ? 0 : type.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            IndexType other = (IndexType) obj;
            if (index == null) {
                if (other.index != null)
                    return false;
            } else if (!index.equals(other.index))
                return false;
            if (type == null) {
                if (other.type != null)
                    return false;
            } else if (!type.equals(other.type))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "IndexType [index=" + index + ", type=" + type + "]";
        }
    }


    public boolean isInitialized() {
        return getRolesSettings() != null && getRolesMappingSettings() != null && getConfigSettings() != null;
    }

    public static class PrivEvalResponse {
        boolean allowed = false;
        Set<String> missingPrivileges = new HashSet<String>();
        Map<String,Set<String>> allowedFlsFields;
        Map<String,Set<String>> maskedFields;
        Map<String,Set<String>> queries;

        public boolean isAllowed() {
            return allowed;
        }
        public Set<String> getMissingPrivileges() {
            return new HashSet<String>(missingPrivileges);
        }

        public Map<String,Set<String>> getAllowedFlsFields() {
            return allowedFlsFields;
        }
        
        public Map<String,Set<String>> getMaskedFields() {
            return maskedFields;
        }

        public Map<String,Set<String>> getQueries() {
            return queries;
        }
        @Override
        public String toString() {
            return "PrivEvalResponse [allowed=" + allowed + ", missingPrivileges=" + missingPrivileges
                    + ", allowedFlsFields=" + allowedFlsFields + ", maskedFields=" + maskedFields + ", queries=" + queries + "]";
        }
        
        
    }

    public PrivEvalResponse evaluate(final User user, String action, final ActionRequest request, Task task) {       
        if (!isInitialized()) {
            throw new ElasticsearchSecurityException("Search Guard is not initialized.");
        }

        final PrivEvalResponse presponse = new PrivEvalResponse();
        presponse.missingPrivileges.add(action);

        if (!enabledFlag) {
            //Ranger Authz disabled. Return from here
            presponse.allowed = true;
            return presponse;
        }

        usrGrpCache.setSettings(getConfigSettings());
        if (rangerPlugin == null) {
            log.error("Ranger Plugin not initialized");
            presponse.allowed = false;
            return presponse;
        }
             
        try {
            if(request instanceof SearchRequest) {
                SearchRequest sr = (SearchRequest) request;                
                if(     sr.source() != null
                        && sr.source().query() == null
                        && sr.source().aggregations() != null
                        && sr.source().aggregations().getAggregatorFactories() != null
                        && sr.source().aggregations().getAggregatorFactories().size() == 1 
                        && sr.source().size() == 0) {
                   AggregationBuilder ab = sr.source().aggregations().getAggregatorFactories().get(0);                   
                   if(     ab instanceof TermsAggregationBuilder 
                           && "terms".equals(ab.getType()) 
                           && "indices".equals(ab.getName())) {                       
                       if("_index".equals(((TermsAggregationBuilder) ab).field()) 
                               && ab.getPipelineAggregations().isEmpty() 
                               && ab.getSubAggregations().isEmpty()) {                  
                           presponse.allowed = true;
                           return presponse;
                       }
                   }
                }
            }
        } catch (Exception e) {
            log.warn("Unable to evaluate terms aggregation",e);
        }
        
        final TransportAddress caller = Objects.requireNonNull((TransportAddress) this.threadContext.getTransient(ConfigConstants.SG_REMOTE_ADDRESS));

        if (log.isDebugEnabled()) {
            log.debug("### evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("requested {} from {}", action, caller);
        }

        if(action.startsWith("internal:indices/admin/upgrade")) {
            action = "indices:admin/upgrade";
            //Add code for Ranger - Admin, _all
            String indexName = "_all";
        }

       final ClusterState clusterState = clusterService.state();
        final MetaData metaData = clusterState.metaData();

        final Tuple<Set<String>, Set<String>> requestedResolvedAliasesIndicesTypes = resolve(user, action, request, metaData);

        final SortedSet<String> requestedResolvedIndices = Collections.unmodifiableSortedSet(new TreeSet<>(requestedResolvedAliasesIndicesTypes.v1()));
        final Set<IndexType> requestedResolvedIndexTypes;

        {
            final Set<IndexType> requestedResolvedIndexTypes0 = new HashSet<IndexType>(requestedResolvedAliasesIndicesTypes.v1().size() * requestedResolvedAliasesIndicesTypes.v2().size());

            for(String index: requestedResolvedAliasesIndicesTypes.v1()) {
                for(String type: requestedResolvedAliasesIndicesTypes.v2()) {
                    requestedResolvedIndexTypes0.add(new IndexType(index, type));
                }
            }

            requestedResolvedIndexTypes = Collections.unmodifiableSet(requestedResolvedIndexTypes0);
        }

        if (log.isDebugEnabled()) {
            log.debug("requested resolved indextypes: {}", requestedResolvedIndexTypes);
        }

        final boolean dnfofEnabled =
                getConfigSettings().getAsBoolean("searchguard.dynamic.kibana.do_not_fail_on_forbidden", false)
                || getConfigSettings().getAsBoolean("searchguard.dynamic.do_not_fail_on_forbidden", false);
        
        if(log.isTraceEnabled()) {
            log.trace("dnfof enabled? {}", dnfofEnabled);
        }
        
        boolean allowAction = false;
        
        final Map<String, Set<IndexType>> leftovers = new HashMap<String, Set<IndexType>>();
        
        //--- check inner bulk requests
        final Set<String> additionalPermissionsRequired = new HashSet<>();
        Set<String> indices = new HashSet<String>();
        Set<String> types = new HashSet<String>();

        log.debug("Action requested: " + action);

        if (request instanceof BulkShardRequest) {
            log.debug("BulkShardRequest");
            final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) request, metaData);
            indices.addAll(t.v1());
            types.addAll(t.v2());
            allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
            presponse.allowed = allowAction;
            
            if (!allowAction) {
                log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
            }
            
            return presponse;

        }
        
        
        if(request instanceof PutMappingRequest) {
            
                log.debug("PutMappingRequest");
            
            PutMappingRequest pmr = (PutMappingRequest) request;
            Index concreteIndex = pmr.getConcreteIndex();
            
            if(concreteIndex != null && (pmr.indices() == null || pmr.indices().length == 0)) {
                String indexName = concreteIndex.getName();
                //Add code for Ranger - Admin
                indices.clear();
                indices.add(indexName);
                allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
            }
        }

        
        if (!(request instanceof CompositeIndicesRequest) 
                && !(request instanceof IndicesRequest)
                && !(request instanceof IndicesAliasesRequest)) {

                log.debug("Request class is {}", request.getClass());
            //Add code for Ranger - Admin
            indices.clear();
            indices.add("_all");
        } else if (request instanceof IndicesAliasesRequest) {
            log.debug("IndicesAliasesRequest");
            
            for(AliasActions ar: ((IndicesAliasesRequest) request).getAliasActions()) {
                final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, ar, metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
            }
            //Add code for Ranger - Admin
            allowAction = checkRangerAuthorization(user, caller, "es_admin", indices, "es_admin") ;
            presponse.allowed = allowAction;
            
            if (!allowAction) {
                log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
            }
            
            return presponse;
            
        } else if (request instanceof CompositeIndicesRequest) {
            log.debug("CompositeIndicesRequest");

            if(request instanceof IndicesRequest) {
                log.debug("IndicesRequest");


                final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) request, metaData);
                indices.addAll(t.v1());
                types.addAll(t.v2());
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof BulkRequest) || (action.equals(BulkAction.NAME)) ) {
                log.debug("BulkRequest");

                for(DocWriteRequest<?> ar: ((BulkRequest) request).requests()) {
                    
                    //TODO SG6 require also op type permissions
                    //require also op type permissions
                    //ar.opType()
                   
                    final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                    //Add code for Ranger - write
 
                }
                allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof MultiGetRequest) || (action.equals(MultiGetAction.NAME))) {
                log.debug("MultiGetRequest");

                for(Item item: ((MultiGetRequest) request).getItems()) {
                    final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, item, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                    //Add code for Ranger - READ
                }
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof MultiSearchRequest) || (action.equals(MultiSearchAction.NAME))) {
                log.debug("MultiSearchRequest");

                for(ActionRequest ar: ((MultiSearchRequest) request).requests()) {
                    final Tuple<Set<String>, Set<String>> t = resolve(user, action, ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                    //Add code for Ranger - READ
                }
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof MultiTermVectorsRequest) || (action.equals(MultiTermVectorsAction.NAME))) {
                log.debug("MultiTermVectorsRequest");

                for(ActionRequest ar: (Iterable<TermVectorsRequest>) () -> ((MultiTermVectorsRequest) request).iterator()) {
                    final Tuple<Set<String>, Set<String>> t = resolve(user, action, ar, metaData);
                    indices.addAll(t.v1());
                    types.addAll(t.v2());
                    //Add code for Ranger - Read
                }
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
                
            } else if((request instanceof ReindexRequest) || (action.equals(ReindexAction.NAME))) {
                log.debug("ReindexRequest");

                ReindexRequest reindexRequest = (ReindexRequest) request;
                Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, reindexRequest.getDestination(), metaData);
                indices.clear();
                indices.addAll(t.v1());
                types.addAll(t.v2());
                allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
                if (!allowAction) {
                    presponse.allowed = allowAction;
                    
                    if (!allowAction) {
                        log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                    }
                    
                    return presponse;
                }
                
                t = resolveIndicesRequest(user, action, reindexRequest.getSearchRequest(), metaData);
                indices.clear();
                indices.addAll(t.v1());
                types.addAll(t.v2());
                //Add code for Ranger - Admin
                allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
                presponse.allowed = allowAction;
                
                if (!allowAction) {
                    log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
                }
                
                return presponse;
            } else {
                log.debug("Can not handle request of type '"+request.getClass().getName()+"'for "+action+" here");
            }

        } else {
            //ccs goes here
            final Tuple<Set<String>, Set<String>> t = resolveIndicesRequest(user, action, (IndicesRequest) request, metaData);
            indices = t.v1();
            types = t.v2();
        }
                        
        log.debug("Action requested: " + action + " , indices: " + String.join(",", indices));
        if (action.startsWith("cluster:monitor/")) {
            indices.clear();
            indices.add("_cluster");
            allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
        } else if (action.startsWith("cluster:")) {
            /* Not clear on following so skipping:
             *             || action.startsWith(SearchScrollAction.NAME)
             *              || (action.equals("indices:data/read/coordinate-msearch"))
             */
            indices.clear();
            indices.add("_cluster");
            allowAction = checkRangerAuthorization(user, caller, "es_admin", indices, "es_admin");
        } else if (action.startsWith("indices:admin/create")
                || (action.startsWith("indices:admin/mapping/put"))) {
            
            allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
        } else if ((action.startsWith("indices:data/read"))
                || (action.startsWith("indices:monitor/"))
                || (action.startsWith("indices:admin/template/get"))
                || (action.startsWith("indices:admin/mapping/get"))
                || (action.startsWith("indices:admin/mappings/get"))
                || (action.startsWith("indices:admin/mappings/fields/get"))
                || (action.startsWith("indices:admin/aliases/exists"))
                || (action.startsWith("indices:admin/aliases/get"))
                || (action.startsWith("indices:admin/exists"))
                || (action.startsWith("indices:admin/get"))){
            //Add code for Ranger - Read
            allowAction = checkRangerAuthorization(user, caller, "read", indices, "read");
        } else if (action.startsWith("indices:data/write")
                || (action.startsWith("indices:data/"))) {
            //Add code for Ranger - Write/Delete
            allowAction = checkRangerAuthorization(user, caller, "write", indices, "write");
        } else if (action.startsWith("indices:")) {
            log.debug("All remaining unknown actions with indices:");

            //Add code for Ranger - Admin
            allowAction = checkRangerAuthorization(user, caller, "es_admin", indices, "es_admin"); 
        } else {
            log.debug("All remaining unknown actions");
            indices.clear();
            indices.add("_cluster");
            allowAction = checkRangerAuthorization(user, caller, "es_admin", indices, "es_admin");
        }

        if (!allowAction) {
            log.info("Permission denied for User: " + user.getName() + "Action: " + action + " , indices: " + String.join(",", indices));
        }
        presponse.allowed = allowAction;
        return presponse;        
    }
    

    private boolean checkRangerAuthorization(final User user, TransportAddress caller, String accessType, Set<String> indices, String clusterLevelAccessType) {
        //String clusterName = rangerPlugin.getClusterName();
        boolean checkClusterLevelPermission = false;
        Date eventTime = new Date();
        String ipAddress = caller.address().getHostString();
        RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl();
        rangerRequest.setUser(user.getName());
        
        Set<String> userGroups = null;
        Set<String> userRoles = user.getRoles();
        if (userRoles != null && !(userRoles.isEmpty())) {
            userGroups = userRoles;
        } else {
            try {
                SecurityManager sm = System.getSecurityManager();
                if (sm != null) {
                    sm.checkPermission(new SpecialPermission());
                }
            
                userGroups = AccessController.doPrivileged(new PrivilegedAction<Set<String>>() {
                    public Set<String> run() {
                        try {
                            return usrGrpCache.getUserGroups(user.getName());
                        } catch (Exception e) {
                            if (log.isDebugEnabled()) {
                                e.printStackTrace();
                            }
                            log.warn("Exception in retrieving user group mapping : " + e.getMessage() );
                        }
                        return null;
                    }
                });
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    e.printStackTrace();
                }
                log.warn("Exception in retrieving user group mapping : " + e.getMessage() );
            }
        }
        
        if (userGroups != null) {
            rangerRequest.setUserGroups(userGroups);
        } else {
            log.warn("No groups found for user : " + user.getName());
        }
        rangerRequest.setClientIPAddress(ipAddress);
        rangerRequest.setAccessTime(eventTime);
        RangerAccessResourceImpl rangerResource = new RangerAccessResourceImpl();
        rangerRequest.setResource(rangerResource);
        rangerRequest.setAccessType(accessType);
        rangerRequest.setAction(accessType);
        //rangerRequest.setClusterName(clusterName);
        
        for (Iterator<String> it = indices.iterator(); it.hasNext();) {
            String index = it.next();
            log.debug("Checking for index: " + index + ", for user: " + user.getName() + " and accessType: " + accessType);
            rangerResource.setValue("index", index);
            RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
            if (result == null || !(result.getIsAllowed())) {
                if ((!index.equals("_all")) && (!index.equals("_cluster"))) {
                    checkClusterLevelPermission = true;
                } else {
                    log.debug("Index/Cluster Permission denied");
                    return false;
                }
            }
        }
        if (checkClusterLevelPermission) {
            log.debug("Checking all level permissions (_all), accessType: " + clusterLevelAccessType);
            rangerResource.setValue("index", "_all");
            rangerRequest.setAccessType(clusterLevelAccessType);
            RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
            if (result == null || !(result.getIsAllowed())) {
                log.debug("All level Permission denied");
                return false;
            }
        }
        return true;
    }
    
     
    //---- end evaluate()
   
   /* 
    private PrivEvalResponse evaluateSnapshotRestore(final User user, String action, final ActionRequest request, final TransportAddress caller, final Task task) {
        
        final PrivEvalResponse presponse = new PrivEvalResponse();
        presponse.missingPrivileges.add(action);
        
        if (!(request instanceof RestoreSnapshotRequest)) {
            return presponse;
        }

        final RestoreSnapshotRequest restoreRequest = (RestoreSnapshotRequest) request;

        // Do not allow restore of global state
        if (restoreRequest.includeGlobalState()) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " with 'include_global_state' enabled is not allowed");
            return presponse;
        }

            if(reduced.isEmpty()) {
                presponse.allowed = false;
                return presponse;
            }
        for (final SnapshotId snapshotId : repository.getRepositoryData().getSnapshotIds()) {
            if (snapshotId.getName().equals(restoreRequest.snapshot())) {

                if(log.isDebugEnabled()) {
                    log.info("snapshot found: {} (UUID: {})", snapshotId.getName(), snapshotId.getUUID());    
                }

                snapshotInfo = repository.getSnapshotInfo(snapshotId);
                break;
            }
        }

        if (snapshotInfo == null) {
            log.warn(action + " for repository '" + restoreRequest.repository() + "', snapshot '" + restoreRequest.snapshot() + "' not found");
            return presponse;
        }

        final List<String> requestedResolvedIndices = SnapshotUtils.filterIndices(snapshotInfo.indices(), restoreRequest.indices(), restoreRequest.indicesOptions());

        if (log.isDebugEnabled()) {
            log.info("resolved indices for restore to: {}", requestedResolvedIndices.toString());
        }
        // End resolve for RestoreSnapshotRequest

        // Check if the source indices contain the searchguard index
        if (requestedResolvedIndices.contains(searchguardIndex) || requestedResolvedIndices.contains("_all")) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '{}' as source index is not allowed", searchguardIndex);
            return presponse;
        }

        // Check if the renamed destination indices contain the searchguard index
        final List<String> renamedTargetIndices = renamedIndices(restoreRequest, requestedResolvedIndices);
        if (renamedTargetIndices.contains(searchguardIndex) || requestedResolvedIndices.contains("_all")) {
            auditLog.logSgIndexAttempt(request, action, task);
            log.warn(action + " for '{}' as target index is not allowed", searchguardIndex);
            return presponse;
        }

        if (log.isDebugEnabled()) {
            log.info("mapped roles: {}", sgRoles);
        }

        boolean allowedActionSnapshotRestore = false;

        final Set<String> renamedTargetIndicesSet = new HashSet<String>(renamedTargetIndices);
        final Set<IndexType> _renamedTargetIndices = new HashSet<IndexType>(renamedTargetIndices.size());
        for(final String index: renamedTargetIndices) {
            for(final String neededAction: ConfigConstants.SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES) {
                _renamedTargetIndices.add(new IndexTypeAction(index, "*", neededAction));
            }
        }


        //not bulk, mget, etc request here
        boolean permGiven = false;

        if (config.getAsBoolean("searchguard.dynamic.multi_rolespan_enabled", false)) {
            permGiven = sgRoles.impliesTypePermGlobal(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);
        }  else {
            permGiven = sgRoles.get(requestedResolved, user, allIndexPermsRequiredA, resolver, clusterService);

        }

         if (!permGiven) {
            log.info("No {}-level perm match for {} {} [Action [{}]] [RolesChecked {}]", "index" , user, requestedResolved, action0, sgRoles.getRoles().stream().map(r->r.getName()).toArray());
            log.info("No permissions for {}", presponse.missingPrivileges);
        } else {

            if(checkFilteredAliases(requestedResolved.getAllIndices(), action0)) {
                presponse.allowed=false;
                return presponse;
            }

            if(log.isDebugEnabled()) {
                log.debug("Allowed because we have all indices permissions for "+action0);
            }
        }

        if (checkSnapshotRestoreWritePrivileges && !_renamedTargetIndices.isEmpty()) {
            allowedActionSnapshotRestore = false;
        }

        if (!allowedActionSnapshotRestore) {
            auditLog.logMissingPrivileges(action, request, task);
            log.debug("No perm match for {} [Action [{}]] [RolesChecked {}]", user, action, sgRoles);
        }
        
        presponse.allowed = allowedActionSnapshotRestore;
        return presponse;

    }
    */

    public Set<String> mapSgRoles(final User user, final TransportAddress caller) {

        final Settings rolesMapping = getRolesMappingSettings();
        final Set<String> sgRoles = new TreeSet<String>();

        if(user == null) {
            return Collections.emptySet();
        }

        if(rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.BACKENDROLES_ONLY) {
            if(log.isDebugEnabled()) {
                log.debug("Pass backendroles from {}", user);
            }
            sgRoles.addAll(user.getRoles());
        }

        if(rolesMapping != null && ((rolesMappingResolution == ConfigConstants.RolesMappingResolution.BOTH
                || rolesMappingResolution == ConfigConstants.RolesMappingResolution.MAPPING_ONLY))) {
            for (final String roleMap : rolesMapping.names()) {
                final Settings roleMapSettings = rolesMapping.getByPrefix(roleMap);

                if (WildcardMatcher.allPatternsMatched(roleMapSettings.getAsList(".and_backendroles", Collections.emptyList()).toArray(new String[0]), user.getRoles().toArray(new String[0]))) {
                    sgRoles.add(roleMap);
                    continue;
                }

                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".backendroles", Collections.emptyList()).toArray(new String[0]), user.getRoles().toArray(new String[0]))) {
                    sgRoles.add(roleMap);
                    continue;
                }

                if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".users"), user.getName())) {
                    sgRoles.add(roleMap);
                    continue;
                }
                
                if(caller != null && log.isTraceEnabled()) {
                    log.trace("caller (getAddress()) is {}", caller.getAddress());
                    log.trace("caller unresolved? {}", caller.address().isUnresolved());
                    log.trace("caller inner? {}", caller.address().getAddress()==null?"<unresolved>":caller.address().getAddress().toString());
                    log.trace("caller (getHostString()) is {}", caller.address().getHostString());
                    log.trace("caller (getHostName(), dns) is {}", caller.address().getHostName()); //reverse lookup
                }
                
                if(caller != null) {
                    //IPV4 or IPv6 (compressed and without scope identifiers)
                    final String ipAddress = caller.getAddress();
                    if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), ipAddress)) {
                        sgRoles.add(roleMap);
                        continue;
                    }
    
                    final String hostResolverMode = getConfigSettings().get("searchguard.dynamic.hosts_resolver_mode","ip-only");
                    
                    if(caller.address() != null && (hostResolverMode.equalsIgnoreCase("ip-hostname") || hostResolverMode.equalsIgnoreCase("ip-hostname-lookup"))){
                        final String hostName = caller.address().getHostString();
        
                        if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), hostName)) {
                            sgRoles.add(roleMap);
                            continue;
                        }
                    }
                    
                    if(caller.address() != null && hostResolverMode.equalsIgnoreCase("ip-hostname-lookup")){
    
                        final String resolvedHostName = caller.address().getHostName();
             
                        if (WildcardMatcher.matchAny(roleMapSettings.getAsList(".hosts"), resolvedHostName)) {
                            sgRoles.add(roleMap);
                            continue;
                        }
                    }
                }
            }
        }

        return Collections.unmodifiableSet(sgRoles);

    }

    public Map<String, Boolean> mapTenants(final User user, final TransportAddress caller) {

        if(user == null) {
            return Collections.emptyMap();
        }

        final Map<String, Boolean> result = new HashMap<>();
        result.put(user.getName(), true);

        for(String sgRole: mapSgRoles(user, caller)) {
            Settings tenants = getRolesSettings().getByPrefix(sgRole+".tenants.");

            if(tenants != null) {
                for(String tenant: tenants.names()) {

                    if(tenant.equals(user.getName())) {
                        continue;
                    }

                    if("RW".equalsIgnoreCase(tenants.get(tenant, "RO"))) {
                        result.put(tenant, true);
                    } else {
                        if(!result.containsKey(tenant)) { //RW outperforms RO
                            result.put(tenant, false);
                        }
                    }
                }
            }

        }

        return Collections.unmodifiableMap(result);
    }



    public boolean multitenancyEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().getAsBoolean("searchguard.dynamic.kibana.multitenancy_enabled", true);
    }

    public boolean notFailOnForbiddenEnabled() {
        return privilegesInterceptor.getClass() != PrivilegesInterceptor.class
                && getConfigSettings().getAsBoolean("searchguard.dynamic.kibana.do_not_fail_on_forbidden", false);
    }

    public String kibanaIndex() {
        return getConfigSettings().get("searchguard.dynamic.kibana.index",".kibana");
    }

    public String kibanaServerUsername() {
        return getConfigSettings().get("searchguard.dynamic.kibana.server_username","kibanaserver");
    }

    private Set<String> evaluateAdditionalIndexPermissions(final ActionRequest request, final String originalAction) {
      //--- check inner bulk requests
        final Set<String> additionalPermissionsRequired = new HashSet<>();

        if(!isClusterPerm(originalAction)) {
            additionalPermissionsRequired.add(originalAction);
        }

        if (request instanceof BulkShardRequest) {
            BulkShardRequest bsr = (BulkShardRequest) request;
            for (BulkItemRequest bir : bsr.items()) {
                switch (bir.request().opType()) {
                case CREATE:
                    additionalPermissionsRequired.add(IndexAction.NAME);
                    break;
                case INDEX:
                    additionalPermissionsRequired.add(IndexAction.NAME);
                    break;
                case DELETE:
                    additionalPermissionsRequired.add(DeleteAction.NAME);
                    break;
                case UPDATE:
                    additionalPermissionsRequired.add(UpdateAction.NAME);
                    break;
                }
            }
        }


        if (!(request instanceof CompositeIndicesRequest) 
                && !(request instanceof IndicesRequest)
                && !(request instanceof IndicesAliasesRequest)) {

            if (log.isDebugEnabled()) {
                log.debug("{} is not an IndicesRequest", request.getClass());
            }
            if (action.startsWith("cluster:")) {
                return new Tuple<Set<String>, Set<String>>(Sets.newHashSet("_cluster"), Sets.newHashSet("_all"));
            }
            return new Tuple<Set<String>, Set<String>>(Sets.newHashSet("_all"), Sets.newHashSet("_all"));
        }
        
        Set<String> indices = new HashSet<String>();
        Set<String> types = new HashSet<String>();
        
        if (request instanceof IndicesAliasesRequest) {
            IndicesAliasesRequest bsr = (IndicesAliasesRequest) request;
            for (AliasActions bir : bsr.getAliasActions()) {
                switch (bir.actionType()) {
                case REMOVE_INDEX:
                    additionalPermissionsRequired.add(DeleteIndexAction.NAME);
                    break;
                default:
                    break;
                }
            }
        }
        
        if (request instanceof CreateIndexRequest) {
            CreateIndexRequest cir = (CreateIndexRequest) request;
            if(cir.aliases() != null && !cir.aliases().isEmpty()) {
                additionalPermissionsRequired.add(IndicesAliasesAction.NAME);
            }
        }

        if(request instanceof RestoreSnapshotRequest && checkSnapshotRestoreWritePrivileges) {
            additionalPermissionsRequired.addAll(ConfigConstants.SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES);
        }

        if(actionTrace.isTraceEnabled() && additionalPermissionsRequired.size() > 1) {
            actionTrace.trace(("Additional permissions required: "+additionalPermissionsRequired));
        }

        if(log.isDebugEnabled() && additionalPermissionsRequired.size() > 1) {
            log.debug("Additional permissions required: "+additionalPermissionsRequired);
        }

        return Collections.unmodifiableSet(additionalPermissionsRequired);
    }

    private static boolean isClusterPerm(String action0) {
        return  (    action0.startsWith("cluster:")
                || action0.startsWith("indices:admin/template/")

            || action0.startsWith(SearchScrollAction.NAME)
            || (action0.equals(BulkAction.NAME))
            || (action0.equals(MultiGetAction.NAME))
            || (action0.equals(MultiSearchAction.NAME))
            || (action0.equals(MultiTermVectorsAction.NAME))
            || (action0.equals("indices:data/read/coordinate-msearch"))
            || (action0.equals(ReindexAction.NAME))

            ) ;
    }

    private boolean checkFilteredAliases(Set<String> requestedResolvedIndices, String action) {
        //check filtered aliases
        for(String requestAliasOrIndex: requestedResolvedIndices) {

            final List<AliasMetaData> filteredAliases = new ArrayList<AliasMetaData>();

            final IndexMetaData indexMetaData = clusterService.state().metaData().getIndices().get(requestAliasOrIndex);

            if(indexMetaData == null) {
                log.debug("{} does not exist in cluster metadata", requestAliasOrIndex);
                continue;
            }

            final ImmutableOpenMap<String, AliasMetaData> aliases = indexMetaData.getAliases();

            if(aliases != null && aliases.size() > 0) {

                if(log.isDebugEnabled()) {
                    log.debug("Aliases for {}: {}", requestAliasOrIndex, aliases);
                }

                final Iterator<String> it = aliases.keysIt();
                while(it.hasNext()) {
                    final String alias = it.next();
                    final AliasMetaData aliasMetaData = aliases.get(alias);

                    if(aliasMetaData != null && aliasMetaData.filteringRequired()) {
                        filteredAliases.add(aliasMetaData);
                        if(log.isDebugEnabled()) {
                            log.debug(alias+" is a filtered alias "+aliasMetaData.getFilter());
                        }
                    } else {
                        if(log.isDebugEnabled()) {
                            log.debug(alias+" is not an alias or does not have a filter");
                        }
                    }
                }
            }

            if(filteredAliases.size() > 1 && WildcardMatcher.match("indices:data/read/*search*", action)) {
                //TODO add queries as dls queries (works only if dls module is installed)
                final String faMode = getConfigSettings().get("searchguard.dynamic.filtered_alias_mode","warn");

                if(faMode.equals("warn")) {
                    log.warn("More than one ({}) filtered alias found for same index ({}). This is currently not recommended. Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                } else if (faMode.equals("disallow")) {
                    log.error("More than one ({}) filtered alias found for same index ({}). This is currently not supported. Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                    return true;
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("More than one ({}) filtered alias found for same index ({}). Aliases: {}", filteredAliases.size(), requestAliasOrIndex, toString(filteredAliases));
                    }
                }
            }
        } //end-for

        return false;
    }

    private List<String> toString(List<AliasMetaData> aliases) {
        if(aliases == null || aliases.size() == 0) {
            return Collections.emptyList();
        }

        final List<String> ret = new ArrayList<>(aliases.size());

        for(final AliasMetaData amd: aliases) {
            if(amd != null) {
                ret.add(amd.alias());
            }
        }

        return Collections.unmodifiableList(ret);
    }
}
