# This script is an example and is NOT intended to be ran directly!

exit

# Set RELEASE version (can't include "SNAPSHOT" in version if we are deploying to main repo)
mvn versions:set -DnewVersion=1.1

# Deploy master-pom (required as dependency for sub-modules)
# Only deploying the POM file here, no source or JARs
mvn deploy -N -P maven-package-and-release -pl com.github.secdec.astam-correlator:master-pom

# Deploy threadfix-ham and threadfix-entities
mvn deploy -P maven-package-and-release -pl threadfix-ham,threadfix-entities,threadfix-cli-lib

# Reset SNAPSHOT version
mvn versions:set -DnewVersion=1.1-SNAPSHOT
