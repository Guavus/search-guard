# Note for editing Makefile : Makefile requires Tab to identify commands


SHELL := /bin/bash


publish-all: \
	clean \
	publish-rpms \

all: \
	clean \
	gather-dist-source-jobs 
		


publish-rpms: \
	gather-dist-source-jobs \
	gather-dist-rpms
	@echo "= = = = = = = > START TARGET : [publish-rpms] < = = = = = = ="
	cd rpm-mgmt; ./deploy_rpms.sh
	@echo "= = = = = = = = > END TARGET : [publish-rpms] < = = = = = = ="


gather-dist-rpms: 
	cd rpm-mgmt; rm -rf .package;  ./build_rpm.sh;  

gather-dist-source-jobs: \
	build-source \
	dist


clean:
	@echo "= = = = = = = > START TARGET : [clean] < = = = = = = ="
	rm -rf dist
	@echo "= = = = = = = = > END TARGET : [clean] < = = = = = = ="


build-source:
	@echo "= = = = = = = > START TARGET : [build-source] < = = = = = = ="
	mvn clean package -DskipTests -Penterprise
	@echo "= = = = = = = = > END TARGET : [build-source] < = = = = = = ="

dist:
	mkdir -p dist/es-searchguard
	mkdir -p dist/installer


.PHONY: publish-all all publish-rpms gather-dist-source-jobs clean build-source dist
