# Guavus Search Guard - Security for Elasticsearch

Guavus Search Guard(®) is an Elasticsearch plugin that offers encryption, authentication, and authorization. It supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens and many more, and includes fine grained role-based access control to clusters, indices. Guavus Search Guard is based on Community Edition of Floragunn Search Guard (check: https://github.com/floragunncom/search-guard). Currently the plugin is only supported for Elasticsearch version 6.2.2

## Floragunn Search Guard Community Edition

Search Guard offers all basic security features for free. The Community Edition of Search Guard can be used for all projects, including commercial projects, at absolutely no cost. The Community Edition includes:

* Full data in transit encryption
* Node-to-node encryption
* Index level access control
* Document type based access control
* User-, role- and permission management
* HTTP basic authentication
* User Impersonation
* Proxy support

## Guavus Open Source Version

The Guavus Open Source Version on Search Guard adds:

* Active Directory / LDAP
* Kerberos / SPNEGO
* Knox JSON web token (JWT) support
* Apache Ranger integration for authorization and policy management
* Audit logging through Apache Ranger to stay compliant with security compliance regulations

## Documentation

Please refer to the [Official documentation](http://docs.search-guard.com) for detailed information

## Building Plugin

To build plugin, please do the following steps:
1. Clone the github repository, ``git clone https://github.com/Guavus/search-guard``
2. ``git checkout release/guavus_es-6.2.2`` and ``cd search-guard``
3. To build plugin zip, run ``make all``
4. To build plugin rpm, run ``make gather-dist-rpms``

## Quick Start

1. Create Kerberos principals and key tab files: one for ES service (on all ES nodes) and other for ranger-es (on ranger nodes)

2. Get the public key from Knox certificate using command (run on Knox server): ``<JAVA_HOME>/bin/keytool -export -alias gateway-identity -rfc -file <any file name eg. /tmp/cert.pem> -keystore <Knox Keystore eg. /usr/hdp/current/knox-server/data/security/keystores/gateway.jks>``. The generated file say /tmp/cert.pem has Knox public key which will be used to configure JWT authentication in ES.

3. Install Elasticsearch

4. Install the Search Guard plugin for your Elasticsearch (currently only version 6.2.2 is supported) using command

```
bin/elasticsearch-plugin install -b file:///home/data/search-guard-6-6.2.2-guavus.zip
```

5. ``cd <ES directory>/plugins/search-guard-<version>/sgconfig`` and Edit file ``sg_config.yml`` and update configs for LDAP, Kerberos, JWT
   - For Kerberos, you can enable/disable Kerberos authentication:
```
      kerberos_auth_domain:
        http_enabled: <true if enabled else false>
```

   - For JWT authentication, if enabled update JWT signing public key:
```
      jwt_auth_domain:
        http_enabled: <true if enabled else false>
        transport_enabled: false
        order: 0
        http_authenticator:
          type: jwt
          challenge: false
          config:
            signing_key: "<Knox Public key eg: MIICSzCCAbSgAwIBAgIIMjJbTiPEbVAwDQYJKoZIhvcNAQEFBQAwaDELMAkGA1UE\nBhMCVVMxDTALBgNVBAgTBFRlc3QxDTALBgNVBAcTBFRlc3QxDzANBgNVBAoTBkhh\nZG9vcDENMAsGA1UECxMEVGVzdDEbMBkGA1UEAxMScmFqYXQtMi5ndWF2dXMuY29t\nMB4XDTE4MDQxMDEwMDI0NloXDTE5MDQxMDEwMDI0NlowaDELMAkGA1UEBhMCVVMx\nDTALBgNVBAgTBFRlc3QxDTALBgNVBAcTBFRlc3QxDzANBgNVBAoTBkhhZG9vcDEN\nMAsGA1UECxMEVGVzdDEbMBkGA1UEAxMScmFqYXQtMi5ndWF2dXMuY29tMIGfMA0G\nCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFMvxDUmIgeoXf7ZFvJ5eHhwSwxbKxvCUw\nqqxhpkog6rf5g4roDCN90xjShcqVpAEDd7rOYKQGemgULgiIDCbwJDazFWZMASbr\nVwuPygEgHz3MgP4G4sQ/xzFbdiavxMk6nTeownWKlNVyAubN84xP8C7VGwK5g8qt\nAVgVCP3ilQIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACxYxpDR+mqGrnlwWV7zcswk\nX9/73a+wYZ9iI4WO2I2z9v0udbd6CZU0QfXYaRGVkHWBRujf4qg3DHebTcXvd52p\niyL5j8I1s25pts+ZGrveI/3A4vSv6T57bQgBzC8Im/cQr+q2P3CJFa65uxIxyQJh\nETID+gC+gugOEMJYefu9>"
```

   - For LDAP, if enabled update LDAP configs
```
      ldap:
        enabled: <true if enabled else false>
        http_enabled: <true if enabled else false>
        transport_enabled: false
        order: 2
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          # LDAP authentication backend (authenticate users against a LDAP or Active Directory)
          type: ldap # NOT FREE FOR COMMERCIAL USE
          config:
            # enable ldaps
            enable_ssl: false
            # enable start tls, enable_ssl should be false
            enable_start_tls: false
            # send client certificate
            enable_ssl_client_auth: false
            # verify ldap hostname
            verify_hostnames: true
            hosts:
              - ldap://<LDAP server IP>:389
            bind_dn: '<DN user to use for LDAP bind and query eg. cn=ldapadm,dc=example,dc=local>'
            password: '<Bind DN password eg. admin>'
            userbase: '<Base to search users from eg. uid={0},ou=People,dc=example,dc=local>'
            usersearch: '<Search filter eg. (objectClass=account)>'
            # Use this attribute from the user as username (if not set then DN is used)
            usergroup_attribute: '<LDAP attribute for group identification eg. gidNumber>'
            groupbase: '<Base to search group names eg. ou=Group,dc=example,dc=local>'
            groupsearch: '<Group search filter eg. (&(objectClass=posixGroup)(gidNumber={1}))>'
            groupname_attribute: '<Group name attribute eg. cn>'
```

NOTE: If Ranger is enabled in ``elasticsearch.yml``, then it is mandatory to enable Kerberos authentication

6. Install demo certificates: Download certificates from ``https://docs.search-guard.com/latest/tls-download-certificates`` and unzip the certificates.zip file in location ``<ES Directory>/config``
7. Add follwing search guard configs in ``elasticsearch.yml``:
```
searchguard.ssl.transport.pemcert_filepath: esnode.pem
searchguard.ssl.transport.pemkey_filepath: esnode-key.pem
searchguard.ssl.transport.pemtrustedcas_filepath: root-ca.pem
searchguard.ssl.transport.enforce_hostname_verification: false
searchguard.ssl.http.enabled: false
searchguard.ssl.http.pemcert_filepath: esnode.pem
searchguard.ssl.http.pemkey_filepath: esnode-key.pem
searchguard.ssl.http.pemtrustedcas_filepath: root-ca.pem
searchguard.allow_unsafe_democertificates: true
searchguard.allow_default_init_sgindex: true
searchguard.authcz.admin_dn:
  - CN=kirk,OU=client,O=client,L=test, C=de
searchguard.audit.type: internal_elasticsearch
searchguard.enable_snapshot_restore_privilege: true
searchguard.check_snapshot_restore_write_privileges: true
searchguard.restapi.roles_enabled: ["sg_all_access"]
discovery.zen.minimum_master_nodes: 1
node.max_local_storage_nodes: 3
searchguard.enterprise_modules_enabled: false
searchguard.kerberos.acceptor_principal: '<Service princiapl for ES eg: HTTP/192.168.154.190@GVS.GGN>'
searchguard.kerberos.acceptor_keytab_filepath: '<Keytab file for above service princiapl eg. /etc/security/keytabs/es.service.keytab>'
searchguard.authz.ranger.enabled: <If Ranger is enabled then true else false>
searchguard.authz.ranger.serviceType: 'elasticsearch'
searchguard.authz.ranger.appId: '<An App id for thi ES instance eg: my_elasticsearch. This AppID will be used in configuring plugin-security.policy file>'
```

8. ``cd <ES directory>/plugins/search-guard-<version>`` and update following lines in file ``plugin-security.policy``:
```
  permission java.io.FilePermission "/etc/ranger/elasticsearch/policycache/<appId>_<serviceName>.json","read,write";
  permission java.io.FilePermission "/etc/ranger/elasticsearch/policycache/<appId>_<serviceName>.json","read,write";
```

9. Copy ``resources`` folder from rpm install path/github to plugin directory using command ``cp -r /opt/guavus/es-searchguard/resources <ES directory>/plugins/search-guard-<version>/.``

10. ``cd <ES directory>/plugins/search-guard-<version>/resources``, edit file ``ranger-elasticsearch-security.xml`` and update following properties:
```
        <property>
                <name>ranger.plugin.elasticsearch.service.name</name>
                <value>mycluster_es</value>
                <description>
                        Name of the Ranger service containing policies for this YARN instance
                </description>
        </property>
        <property>
                <name>ranger.plugin.elasticsearch.policy.rest.url</name>
                <value>http://<IP>:6080</value>
                <description>
                        URL to Ranger Admin
                </description>
        </property>
```

11. ``cd <ES directory>/plugins/search-guard-<version>/resources``, edit file ``ranger-elasticsearch-audit.xml`` for appropriate audit log destination, typically solr with following properties:
```
       <property>
                <name>xasecure.audit.destination.solr</name>
                <value>false</value>
        </property>

        <property>
                <name>xasecure.audit.destination.solr.urls</name>
                <value>NONE</value>
        </property>

        <property>
                <name>xasecure.audit.destination.solr.zookeepers</name>
                <value></value>
        </property>

        <property>
                <name>xasecure.audit.destination.solr.collection</name>
                <value>NONE</value>
        </property>
```

12. Start Elasticsearch on all nodes


**NOTE: Step 3 onwards has to be done on all ES nodes.

## Support

* Community support for Floragunn Search Guard available via [google groups](https://groups.google.com/forum/#!forum/search-guard)

## Legal 

Elasticsearch, Kibana and Logstash are trademarks of Elasticsearch BV, registered in the U.S. and in other countries. 
