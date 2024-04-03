# This is a configuration file for Tognix Java Gateway.
# It is sourced by startup.sh and shutdown.sh scripts.

### Option: listenIP
#	IP address to listen on.
#
# Mandatory: no
# Default:
# LISTEN_IP="0.0.0.0"

### Option: listenPort
#	Port to listen on.
#
# Mandatory: no
# Range: 1024-32767
# Default:
# LISTEN_PORT=10052

### Option: pidFile
#	Name of PID file.
#	If omitted, Tognix Java Gateway is started as a console application.
#
# Mandatory: no
# Default:
# PID_FILE=

PID_FILE="/usr/local/tognix/data/tognix_java.pid"

### Option: startPollers
#	Number of worker threads to start.
#
# Mandatory: no
# Range: 1-1000
# Default:
# START_POLLERS=5

### Option: timeout
#	How long to wait for network operations.
#
# Mandatory: no
# Range: 1-30
# Default:
# TIMEOUT=3

### Option: propertiesFile
#	Name of properties file. Can be used to set additional properties in a such way that they are not visible on
#	a command line or to overwrite existing ones.
# Mandatory: no
# Default:
# PROPERTIES_FILE=

# uncomment to enable remote monitoring of the standard JMX objects on the Tognix Java Gateway itself
#JAVA_OPTIONS="$JAVA_OPTIONS -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.port=12345
#	-Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false
#	-Dcom.sun.management.jmxremote.registry.ssl=false"
