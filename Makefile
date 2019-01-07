# Note for editing Makefile : Makefile requires Tab to identify commands


SHELL := /bin/bash
REL_VERSION := $(shell cat .VERSION)

all: \
	clean \
	gather-dist-source-jobs 
		
gather-dist-rpms: 
	cd rpm-mgmt; rm -rf .package;  ./build_rpm.sh $(REL_VERSION) 0;  

gather-dist-source-jobs: \
	build-source \
	dist


clean:
	@echo "= = = = = = = > START TARGET : [clean] < = = = = = = ="
	rm -rf dist
	rm -rf target
	@echo "= = = = = = = = > END TARGET : [clean] < = = = = = = ="


build-source:
	@echo "= = = = = = = > START TARGET : [build-source] < = = = = = = ="
	mvn clean package -DskipTests -Penterprise
	@echo "= = = = = = = = > END TARGET : [build-source] < = = = = = = ="

dist:
	mkdir -p dist/es-searchguard
	mkdir -p dist/installer


.PHONY: all gather-dist-source-jobs clean build-source dist
