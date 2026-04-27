#!/bin/ksh93

JAVA_HOME=${JAVA_HOME:-/opt/jdk}
[[ ! -e ${JAVA_HOME} ]] && JAVA_HOME=/usr/jdk

# Flags for the Java Virtual Machine to use on start as well as on shutdown
JVM_FLAGS=( '-Djava.awt.headless=true' )

# Flags for the Java Virtual Machine to use on start, only.
START_JVM_FLAGS=(
	## JMX can be used to retrieve server information and statistics on demand.

	# JMX clients connect to this TCP port to access the RMI registry.
	'-Dcom.sun.management.jmxremote.port=12345'

	# TCP port used for JMX RMI client connections. If not set, a random port
	# is selected as needed, which can be difficult to handle with firewalls.
	#'-Dcom.sun.management.jmxremote.rmi.port=12346'

	# Force JMX clients to use this IP or hostname/FQDN
	#'-Djava.rmi.server.hostname=127.0.0.1'

	# If a firewall is in place which allows only trusted clients within the
	# local network to connect, no authentication and no traffic encryption is
	# probably ok. If in doubts, inverse these settings.
	'-Dcom.sun.management.jmxremote.authenticate=false'
	'-Dcom.sun.management.jmxremote.ssl=false'

	# No dynamic class loading from remote codebases (security best practice).
	'-Djava.rmi.server.useCodebaseOnly=true'

	# For additional options, consult the JMX documentation or ask ChatGPT.

	## Other flags
	'-server'
	'-Xmx256m'
	#'-XX:+HeapDumpOnOutOfMemoryError'

	# Just in case someone wants to attach a debugger from remote.
	#'-agentlib:jdwp=transport=dt_socket,address=45678,server=y,suspend=n'
)

# Flags for the Java Virtual Machine to use on shutdown, only.
STOP_JVM_FLAGS=(
)

#=========================================================================
# no further changes required
#=========================================================================
export LC_CTYPE=de_DE.UTF-8

typeset -r VERSION='1.0' PRG=${.sh.file} PROG=${PRG##*/} SDIR=${PRG%/*} \
	BASE_DIR=${SDIR%/*}

function showUsage {
	getopts -a "${PROG}" "${ print ${USAGE} ; }" OPT --man
}

USAGE='[-?$Id: run.sh 703 2014-04-16 02:07:34Z elkner $ ]
[-copyright?Copyright (c) 2007-2026 Jens Elkner. All rights reserved.]
[-license?Proprietary!]
[+NAME?'"${PROG}"' - script to start/stop jelmilter]
[+DESCRIPTION?This script starts per default the jelmilter daemon. If any other of the options below is given, jelmilter just executes the given operation using by default the log configuration in '"${BASE_DIR}"'/lib/test/ if available (e.g. logback-test.xml) and exits.]
[h:help?Print this help and exit.]
[c:config]:[file?The jelmilter daemon configuration file to use. Default: \b/etc/mail/milter.conf\b.]
[e:helo?Do a HELO check and exit. Without any \aoperand\a a help message gets printed explaining possible operands and formats.]
[k:kill?Shutdown the jelmilter daemon and exit. It uses the values from the related configuration to connect to the daemon and send it the signal to shutdown.]
[L:log]:[file?Use the given \afile\a for logging configuration. Must be a logback XML configuration file.]
[m:mbox]:[file?Read the given \bmbox\b formatted \afile\a, dump each mail in it into a separate file to [\bjava.io.tmpdir\b|\b/tmp\b]]\b/mail/\b , extract all URIs, dump a history about domains found in it and exit. If an \boperand\b is given, it will be used as the name of the file, where the dump gets stored (Default: stdout).]
[r:regex]:[file?Check the \bmbox\b formatted \afile\a wrt. to the expressions stored in the default configuration file \b/etc/mail/regex.conf\b and exit. If an \aoperand\a is given, this one will be treaded as the regex config file to use instead of the default one.]
[w:whois]:[cfg_string?Make a whois-spam check and exit. \bcfg_string\b is the configuration string with the format: "\aserver\a\b:\b\aport\a[\b|\b\aserver\a\b:\b\aport\a]]...[\b,skip4=\b\a...\a]][\b,maxsize=\a...\a]]". The \aoperand\a is the name of the \bmbox\b  formatted file to analyze.]
[v:version?Print the current version and exit.]
\n\n[\aoperand\a]...
'

unset ARGS CFG START_CLASS ; typeset -a ARGS
integer IS_START_STOP=1
typeset -n FLAGS=START_JVM_FLAGS

while getopts "${USAGE}" OPT ; do
	case "${OPT}" in
		h) showUsage ; exit 0 ;;
		c) CFG="${OPTARG}" ;;
		r) START_CLASS=de.ovgu.cs.jelmilter.RegexCheck
			ARGS=( "${OPTARG}" )
			IS_START_STOP=0
			;;
		k) START_CLASS=de.ovgu.cs.milter4j.Server IS_START_STOP=2 ;;
		e) START_CLASS=de.ovgu.cs.jelmilter.HeloCheck IS_START_STOP=0 ;;
		w) START_CLASS=de.ovgu.cs.jelmilter.WhoisCheck IS_START_STOP=0
			ARGS=( "${OPTARG}" )
			;;
		m) START_CLASS=de.ovgu.cs.jelmilter.misc.MboxReader	IS_START_STOP=0
			ARGS=( "${OPTARG}" )
			;;
		v) START_CLASS=de.ovgu.cs.jelmilter.Version IS_START_STOP=0 ;;
		L) JVM_FLAGS+=( "-Dlogback.config-file=${OPTARG}" ) ;;
	esac
done
X=$((OPTIND-1))
shift $X

if (( IS_START_STOP )); then
	START_CLASS=de.ovgu.cs.milter4j.Server
	unset ARGS
	[[ -n ${CFG} ]] && ARGS=( "${CFG}" )
	if (( IS_START_STOP == 2 )); then
		typeset -n FLAGS=STOP_JVM_FLAGS
		ARGS+=( 'shutdown' )
	fi
else
	for ((I=${#START_JVM_FLAGS}-1; I >= 0; I-- )); do
		if [[ ${START_JVM_FLAGS[I]} =~ port= ]]; then
			START_JVM_FLAGS[I]='-esa'
		fi
	done
fi

# Prefer java from JAVA_HOME and fallback to PATH if not already set.
[[ -n ${JAVA_HOME} ]] && [[ -x ${JAVA_HOME}/bin/java ]] && \
	JAVA=${JAVA_HOME}/bin/java
[[ -z ${JAVA} || ! -x ${JAVA} ]] && JAVA=${ whence java ; }
if [[ -z ${JAVA} || ! -x ${JAVA} ]]; then
	print -u2 'JVM not found. Set JAVA_HOME or PATH env variable!'
	exit 1
fi

if [[ ! -d ${BASE_DIR}/lib ]]; then
	print -u2 "Base directory ${BASE_DIR}/lib does not exist. Exiting."
	exit 2
fi

# add in the dependency .jar files
(( IS_START_STOP )) && X= || X=":${BASE_DIR}/lib/test"
for F in ~(N)${BASE_DIR}/lib/*.jar ${BASE_DIR}/lib ; do
	[[ ${F: -8:8} == '-src.jar' ]] && continue
	X+=":$F"
done

[[ -d ${BASE_DIR}/lib/endorsed ]] && \
	FLAGS+=( "-Djava.endorsed.dirs=${BASE_DIR}/lib/endorsed" )
[[ -n $X  ]] && FLAGS+=( '-cp' "${X:1}" )

exec ${JAVA} "${JVM_FLAGS[@]}" "${FLAGS[@]}" ${START_CLASS} "${ARGS[@]}" "$@"

# vim: ts=4 sw=4 filetype=sh
