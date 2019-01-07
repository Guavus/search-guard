set -e

pushd "$(dirname "$0")"

TEMP_PACKAGE_DIR=`pwd -P`"/.package"    #"${TEMP_RPM_DIR}/package"
RPM_BASE_PATH="/opt/guavus/es-searchguard/"
DIST_DIR_PLUGIN="./dist/es-searchguard"
DIST_DIR_INSTALLER="./dist/installer"

VERSION=$1
REL=$2

if [ -z "$BUILD_NUMBER" ]
then
      echo "BUILD_NUMBER is not set. setting it 0"
      BUILD_NUMBER=0
fi

 echo "###### START: RPM CREATION ELASTICSEARCH SEARCH GUARD PLUGIN ######"
 echo -e "# # # # # # # START : Creating RPM package # # # # # # #"
    #cleanup
 rm -rf ${TEMP_PACKAGE_DIR}/*
 mkdir -p ${TEMP_PACKAGE_DIR}/${RPM_BASE_PATH}
 mkdir -p ${TEMP_PACKAGE_DIR}/${RPM_BASE_PATH}/resources
 RPM_NAME="guavus-es-searchguard-plugin"
 cp -r ./target/releases/* ${TEMP_PACKAGE_DIR}/${RPM_BASE_PATH}
 cp -r ./certificates.zip ${TEMP_PACKAGE_DIR}/${RPM_BASE_PATH}
 cp -r ./Ranger/resources/* ${TEMP_PACKAGE_DIR}/${RPM_BASE_PATH}/resources
 fpm -f -s dir -t rpm --rpm-os linux -v ${VERSION} --iteration $REL --chdir $TEMP_PACKAGE_DIR -p $DIST_DIR_PLUGIN -n $RPM_NAME .
 echo "###### END: RPM CREATION FOR ELASTICSEARCH SEARCH GUARD PLUGIN ######"

 rm -rf ${TEMP_PACKAGE_DIR}

popd > /dev/null
