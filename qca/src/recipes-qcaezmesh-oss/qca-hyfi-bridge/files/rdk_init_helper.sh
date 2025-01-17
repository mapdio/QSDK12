#!/bin/sh
# Copyright (C) 2006-2014 OpenWrt.org
# Copyright (C) 2006 Fokus Fraunhofer <carsten.tittel@fokus.fraunhofer.de>
# Copyright (C) 2010 Vertical Communications
#
# Copyright (c) 2023, Qualcomm Innovation Center, Inc. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

debug () {
        ${DEBUG:-:} "$@"
}

# newline
N="
"

_C=0
NO_EXPORT=1
LOAD_STATE=1
LIST_SEP=" "
global_context=""

append() {
        local var="$1"
        local value="$2"
        local sep="${3:- }"

        eval "export ${NO_EXPORT:+-n} -- \"$var=\${$var:+\${$var}\${value:+\$sep}}\$value\""
}

list_contains() {
        local var="$1"
        local str="$2"
        local val

        eval "val=\" \${$var} \""
        [ "${val%% $str *}" != "$val" ]
}

config_load() {
        global_context="$1"
        #`syscfg set init_context $1`
        #`syscfg commit`
}

reset_cb() {
        config_cb() { return 0; }
        option_cb() { return 0; }
        list_cb() { return 0; }
}
reset_cb

package() {
        return 0
}

config () {
        local cfgtype="$1"
        local name="$2"

        export ${NO_EXPORT:+-n} CONFIG_NUM_SECTIONS=$(($CONFIG_NUM_SECTIONS + 1))
        name="${name:-cfg$CONFIG_NUM_SECTIONS}"
        append CONFIG_SECTIONS "$name"
        [ -n "$NO_CALLBACK" ] || config_cb "$cfgtype" "$name"
        export ${NO_EXPORT:+-n} CONFIG_SECTION="$name"
        export ${NO_EXPORT:+-n} "CONFIG_${CONFIG_SECTION}_TYPE=$cfgtype"
}

option () {
        local varname="$1"; shift
        local value="$*"

        export ${NO_EXPORT:+-n} "CONFIG_${CONFIG_SECTION}_${varname}=$value"
        [ -n "$NO_CALLBACK" ] || option_cb "$varname" "$*"
}

list() {
        local varname="$1"; shift
        local value="$*"
        local len

        config_get len "$CONFIG_SECTION" "${varname}_LENGTH" 0
        [ $len = 0 ] && append CONFIG_LIST_STATE "${CONFIG_SECTION}_${varname}"
        len=$(($len + 1))
        config_set "$CONFIG_SECTION" "${varname}_ITEM$len" "$value"
        config_set "$CONFIG_SECTION" "${varname}_LENGTH" "$len"
        append "CONFIG_${CONFIG_SECTION}_${varname}" "$value" "$LIST_SEP"
        list_cb "$varname" "$*"
}

config_unset() {
        config_set "$1" "$2" ""
}

# config_get <variable> <section> <option> [<default>]
# config_get <section> <option>
config_get() {
	local context
	local ret_val
	context="$global_context"
	if [ "$global_context" == "ezlbd" ]; then
		eval "${1}=\${4}"
		return 0
	else
		ret_val=`syscfg get $context.$2.$3`
		if [ -n "$ret_val" ]; then
				eval "${1}=\${ret_val}"
		else
				eval "${1}=\${4}"
		fi
	fi
}

# config_get_bool <variable> <section> <option> [<default>]
config_get_bool() {
        local _tmp
        config_get _tmp "$2" "$3" "$4"
        case "$_tmp" in
                1|on|true|yes|enabled) _tmp=1;;
                0|off|false|no|disabled) _tmp=0;;
                *) _tmp="$4";;
        esac
        export ${NO_EXPORT:+-n} "$1=$_tmp"
}

config_set() {
	local section="$1"
	local option="$2"
	local value="$3"
	local context="$global_context"

	ret=`syscfg set "${context}.${section}.${option} ${value}"`
	ret=`syscfg commit`
}

config_foreach() {
        local ___function="$1"
        [ "$#" -ge 1 ] && shift
        local ___type="$1"
        [ "$#" -ge 1 ] && shift
        local section cfgtype

	wireless_section=`syscfg get wireless_section`

	[ -z "$wireless_section" ] && return 0

	for section in ${wireless_section}; do
		cfgtype=`syscfg get wireless."$section".TYPE`
		if [[ $___type != $cfgtype ]]
		then
			continue
		fi
			eval "$___function \"\$section\" \"\$@\""
	done
}

config_list_foreach() {
        [ "$#" -ge 3 ] || return 0
        local section="$1"; shift
        local option="$1"; shift
        local function="$1"; shift
        local val
        local len=1
        local c=1

	[ -z "$len" ] && return 0
	while [ $c -le "$len" ]; do
		config_get val "${section}" "${option}_ITEM$c"
		eval "$function \"\$val\" \"\$@\""
		c="$(($c + 1))"
	done
}

insert_modules() {
        for m in $*; do
                if [ -f /etc/modules.d/$m ]; then
                        sed 's/^[^#]/insmod &/' /etc/modules.d/$m | ash 2>&- || :
                else
                        modprobe $m
                fi
        done
}

default_prerm() {
        local name
        name=$(basename ${1%.*})
        [ -f /usr/lib/opkg/info/${name}.prerm-pkg ] && . /usr/lib/opkg/info/${name}.prerm-pkg
        for i in `cat /usr/lib/opkg/info/${name}.list | grep "^/etc/init.d/"`; do
                $i disable
                $i stop
        done
}

default_postinst() {
        local pkgname rusers ret
        ret=0
        pkgname=$(basename ${1%.*})
        rusers=$(grep "Require-User:" ${IPKG_INSTROOT}/usr/lib/opkg/info/${pkgname}.control)
        [ -n "$rusers" ] && {
                local user group uid gid
                for a in $(echo $rusers | sed "s/Require-User://g"); do
                        user=""
                        group=""
                        for b in $(echo $a | sed "s/:/ /g"); do
                                local ugname ugid

                                ugname=$(echo $b | cut -d= -f1)
                                ugid=$(echo $b | cut -d= -f2)

                                [ -z "$user" ] && {
                                        user=$ugname
                                        uid=$ugid
                                        continue
                                }

                                gid=$ugid
                                [ -n "$gid" ] && {
                                        group_exists $ugname || group_add $ugname $gid
                                }

                                [ -z "$gid" ] && {
                                        group_add_next $ugname
                                        gid=$?
                                }

                                [ -z "$group" ] && {
                                        user_exists $user || user_add $user "$uid" $gid
                                        group=$ugname
                                        continue
                                }

                                group_add_user $ugname $user
                        done
                done
        }

        if [ -f ${IPKG_INSTROOT}/usr/lib/opkg/info/${pkgname}.postinst-pkg ]; then
                ( . ${IPKG_INSTROOT}/usr/lib/opkg/info/${pkgname}.postinst-pkg )
                ret=$?
        fi
        [ -n "${IPKG_INSTROOT}" ] || rm -f /tmp/luci-indexcache 2>/dev/null

        [ "$PKG_UPGRADE" = "1" ] || for i in `cat ${IPKG_INSTROOT}/usr/lib/opkg/info/${pkgname}.list | grep "^/etc/init.d/"`; do
                [ -n "${IPKG_INSTROOT}" ] && $(which bash) ${IPKG_INSTROOT}/etc/rc.common ${IPKG_INSTROOT}$i enable; \
                [ -n "${IPKG_INSTROOT}" ] || {
                        $i enable
                        $i start
                }
        done
        return $ret
}

include() {
        local file

        for file in $(ls $1/*.sh 2>/dev/null); do
                . $file
        done
}

group_add() {
        local name="$1"
        local gid="$2"
        local rc
        [ -f "${IPKG_INSTROOT}/etc/group" ] || return 1
        [ -n "$IPKG_INSTROOT" ] || lock /var/lock/group
        echo "${name}:x:${gid}:" >> ${IPKG_INSTROOT}/etc/group
        rc=$?
        [ -n "$IPKG_INSTROOT" ] || lock -u /var/lock/group
        return $rc
}

group_exists() {
        grep -qs "^${1}:" ${IPKG_INSTROOT}/etc/group
}

group_add_next() {
        local gid gids
        gid=$(grep -s "^${1}:" ${IPKG_INSTROOT}/etc/group | cut -d: -f3)
        [ -n "$gid" ] && return $gid
        gids=$(cat ${IPKG_INSTROOT}/etc/group | cut -d: -f3)
        gid=100
        while [ -n "$(echo $gids | grep $gid)" ] ; do
                gid=$((gid + 1))
        done
        group_add $1 $gid
        return $gid
}

group_add_user() {
        local grp delim=","
        grp=$(grep -s "^${1}:" ${IPKG_INSTROOT}/etc/group)
        [ -z "$(echo $grp | cut -d: -f4 | grep $2)" ] || return
        [ -n "$(echo $grp | grep ":$")" ] && delim=""
        [ -n "$IPKG_INSTROOT" ] || lock /var/lock/passwd
        sed -i "s/$grp/$grp$delim$2/g" ${IPKG_INSTROOT}/etc/group
        [ -n "$IPKG_INSTROOT" ] || lock -u /var/lock/passwd
}

user_add() {
        local name="${1}"
        local uid="${2}"
        local gid="${3}"
        local desc="${4:-$1}"
        local home="${5:-/var/run/$1}"
        local shell="${6:-/bin/false}"
        local rc
        [ -z "$uid" ] && {
                uids=$(cat ${IPKG_INSTROOT}/etc/passwd | cut -d: -f3)
                uid=100
                while [ -n "$(echo $uids | grep $uid)" ] ; do
                        uid=$((uid + 1))
                done
        }
        [ -z "$gid" ] && gid=$uid
        [ -f "${IPKG_INSTROOT}/etc/passwd" ] || return 1
        [ -n "$IPKG_INSTROOT" ] || lock /var/lock/passwd
        echo "${name}:x:${uid}:${gid}:${desc}:${home}:${shell}" >> ${IPKG_INSTROOT}/etc/passwd
        echo "${name}:x:0:0:99999:7:::" >> ${IPKG_INSTROOT}/etc/shadow
        rc=$?
        [ -n "$IPKG_INSTROOT" ] || lock -u /var/lock/passwd
        return $rc
}

user_exists() {
        grep -qs "^${1}:" ${IPKG_INSTROOT}/etc/passwd
}
