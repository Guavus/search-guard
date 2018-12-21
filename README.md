# Guavus Search Guard - Security for Elasticsearch

Guavus Search Guard(®) is an Elasticsearch plugin that offers encryption, authentication, and authorization. It supports authentication via Active Directory, LDAP, Kerberos, JSON web tokens and many more, and includes fine grained role-based access control to clusters, indices, documents and fields

Guavus Search Guard is based on Community Edition of Floragunn Search Guard (check: https://github.com/floragunncom/search-guard)

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
1. Clone the github repository, 'git clone https://github.com/Guavus/search-guard'
2. git checkout release/guavus_es-6.2.2
2. Run 'mvn clean package -DskipTests -Penterprise'

## Quick Start

* Install Elasticsearch

* Install the Search Guard plugin for your Elasticsearch (currently only version 6.2.2 is supported)

```
bin/elasticsearch-plugin install -b file:///home/data/search-guard-6-6.2.2-guavus.zip
```

* ``cd`` into ``<ES directory>/plugins/search-guard-<version>/sgconfig`` and Edit file sg_config.yml and add configs for ldap, kerberos, JWT
* Install demo certificates: Download certificates from https://docs.search-guard.com/latest/tls-download-certificates and unzip the certificates.zip file in location <ES Directory>/config
* Add search guard configs in elasticsearch.yml
* ``cd`` into ``<ES directory>/plugins/search-guard-<version>`` and Edit file plugin-security.policy
* ``cd`` into ``<ES directory>/plugins/search-guard-<version>/resources`` and Edit file anger-elasticsearch-security.xml
* ``cd`` into ``<ES directory>/plugins/search-guard-<version>/resources`` and Edit file ranger-elasticsearch-audit.xml
* Start Elasticsearch

* Display information about the currently logged in user by visiting ``https://localhost:9200/_searchguard/authinfo``.

## Support

* Community support for Floragunn Search Guard available via [google groups](https://groups.google.com/forum/#!forum/search-guard)

## Legal 

Elasticsearch, Kibana and Logstash are trademarks of Elasticsearch BV, registered in the U.S. and in other countries. 
