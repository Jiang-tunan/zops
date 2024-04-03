#!/bin/sh

cd `dirname $0`
. ./settings.sh

if [ -n "$PID_FILE" -a -f "$PID_FILE" ]; then
	PID=`cat "$PID_FILE"`
	if ps -p "$PID" > /dev/null 2>&1; then
		echo "Tognix Java Gateway is already running"
		exit 1
	fi
	rm -f "$PID_FILE"
fi

JAVA=${JAVA:-java}

JAVA_OPTIONS="$JAVA_OPTIONS -server"
if [ -z "$PID_FILE" ]; then
	JAVA_OPTIONS="$JAVA_OPTIONS -Dlogback.configurationFile=logback-console.xml"
fi

CLASSPATH="lib"
for jar in lib/*.jar bin/*.jar; do
	CLASSPATH="$CLASSPATH:$jar"
done

TOGNIX_OPTIONS=""
if [ -n "$PID_FILE" ]; then
	TOGNIX_OPTIONS="$TOGNIX_OPTIONS -DpidFile=$PID_FILE"
fi
if [ -n "$LISTEN_IP" ]; then
	TOGNIX_OPTIONS="$TOGNIX_OPTIONS -DlistenIP=$LISTEN_IP"
fi
if [ -n "$LISTEN_PORT" ]; then
	TOGNIX_OPTIONS="$TOGNIX_OPTIONS -DlistenPort=$LISTEN_PORT"
fi
if [ -n "$START_POLLERS" ]; then
	TOGNIX_OPTIONS="$TOGNIX_OPTIONS -DstartPollers=$START_POLLERS"
fi
if [ -n "$TIMEOUT" ]; then
	TOGNIX_OPTIONS="$TOGNIX_OPTIONS -Dtimeout=$TIMEOUT"
fi
if [ -n "$PROPERTIES_FILE" ]; then
	TOGNIX_OPTIONS="$TOGNIX_OPTIONS -DpropertiesFile=$PROPERTIES_FILE"
fi

tcp_timeout=${TIMEOUT:=3}000
TOGNIX_OPTIONS="$TOGNIX_OPTIONS -Dsun.rmi.transport.tcp.responseTimeout=$tcp_timeout"

COMMAND_LINE="$JAVA $JAVA_OPTIONS -classpath $CLASSPATH $TOGNIX_OPTIONS com.tognix.gateway.JavaGateway"

if [ -n "$PID_FILE" ]; then

	# check that the PID file can be created

	touch "$PID_FILE"
	if [ $? -ne 0 ]; then
		echo "Tognix Java Gateway did not start: cannot create PID file"
		exit 1
	fi

	# start the gateway and output pretty errors to the console

	STDOUT=`$COMMAND_LINE & echo $! > "$PID_FILE"`
	if [ -n "$STDOUT" ]; then
		echo "$STDOUT"
	fi

	# verify that the gateway started successfully

	PID=`cat "$PID_FILE"`
	ps -p "$PID" > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "Tognix Java Gateway did not start"
		rm -f "$PID_FILE"
		exit 1
	fi

else
	exec $COMMAND_LINE
fi
