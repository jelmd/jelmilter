#!/bin/ksh93

JAVA_HOME=${JAVA_HOME:-/opt/jdk}
[[ ! -e ${JAVA_HOME} ]] && JAVA_HOME=/usr/jdk

# Flags for the Java Virtual Machine to use on start as well as on shutdown
JVM_FLAGS=( '-Djava.awt.headless=true' )

# Flags for the Java Virtual Machine to use on start
START_JVM_FLAGS=(
	"${JVM_FLAGS[@]}"

	# enable JMX tools to get info about the server and its stats from remote
	'-Dcom.sun.management.jmxremote.port=12345'

	# if one has no firewalls, dedicated connection machines one would probably
	# inverse these settings
	'-Dcom.sun.management.jmxremote.authenticate=false'
	'-Dcom.sun.management.jmxremote.ssl=false'

	# other flags
	'-server'
	'-Xmx256m'
	#'-XX:+HeapDumpOnOutOfMemoryError'
	
	# just in case, somebody wants to attach a debugger from remote
	#'-agentlib:jdwp=transport=dt_socket,address=45678,server=y,suspend=n'
)

# Flags for the Java Virtual Machine to use on shutdown
STOP_JVM_FLAGS=(
	"${JVM_FLAGS[@]}"
)

#=========================================================================
# no further changes required
#=========================================================================
START_CLASS=de.ovgu.cs.milter4j.Server
export LC_CTYPE=de_DE.UTF-8

# resolv links to base directory
PRG=${.sh.file}
progname=${PRG##*/}
BASE_DIR=${PRG%/*}
BASE_DIR=${PRG%/*}

USAGE='[-?$Id$ ]
[-copyright?Copyright (c) 2007-2014 Jens Elkner. All rights reserved.]
[-license?Proprietary!]
[+NAME?'"${progname}"' - script to start/stop jelmilter]
[+DESCRIPTION?This script starts per default the jelmilter daemon. If any other of the options below is given, jelmilter just executes the given operation and exits.]
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

JAVA=${ whence java ; }
[[ -n ${JAVA_HOME} ]] && [[ -x ${JAVA_HOME}/bin/java ]] && \
	JAVA=${JAVA_HOME}/bin/java

if [[ ! -x ${JAVA} ]]; then
	print -u2 'JVM not found. Set JAVA_HOME or PATH env variable!'
	exit 1
fi

[[ -z ${JVM_FLAGS} ]] && JVM_FLAGS=' '
unset ARGS ; typeset -a ARGS

function showUsage {
	getopts -a "${progname}" "${ print ${USAGE} ; }" OPT --man
}

integer IS_START_STOP=1

typeset -n FLAGS=START_JVM_FLAGS
CFG=''

while getopts "${USAGE}" option ; do
	case "$option" in
		h) showUsage ; exit 0 ;;
		c) CFG="${OPARG}" ;;
		r) START_CLASS=de.ovgu.cs.jelmilter.RegexCheck
			ARGS=( "${OPTARG}" )
			IS_START_STOP=0
			;;
		k) START_CLASS=de.ovgu.cs.milter4j.Server
			IS_START_STOP=2
			;;
		e) START_CLASS=de.ovgu.cs.jelmilter.HeloCheck
			IS_START_STOP=0
			;;
		w) START_CLASS=de.ovgu.cs.jelmilter.WhoisCheck
			ARGS=( "${OPTARG}" )
			IS_START_STOP=0
			;;
		m) START_CLASS=de.ovgu.cs.jelmilter.misc.MboxReader
			ARGS=( "${OPTARG}" )
			IS_START_STOP=0
			;;
		v) START_CLASS=de.ovgu.cs.jelmilter.Version
			IS_START_STOP=0
			;;
		L) JVM_FLAGS+=( "-Dlogback.config-file=$OPTARG" ) ;;
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
fi

if [[ ! -d ${BASE_DIR}/lib ]]; then
	print -u2 "Base directory ${BASE_DIR}/lib does not exist. Exiting."
	exit 2
fi

# add in the dependency .jar files
X=''
for F in ~(N)${BASE_DIR}/lib/*.jar ${BASE_DIR}/lib ; do
	X+=":$F"
done
[[ -d ${BASE_DIR}/lib/endorsed ]] && \
	FLAGS+=( "-Djava.endorsed.dirs=${BASE_DIR}/lib/endorsed" )
[[ -n $X  ]] && FLAGS+=( '-cp' "${X:1}" )

exec ${JAVA} "${FLAGS[@]}" ${START_CLASS} "${ARGS[@]}" "$@"

# vim: ts=4 sw=4 filetype=sh
