#!/bin/sh

APPNAME=hello-efl
SRCROOT=..
POTFILES=POTFILES.in

ALL_LINGUAS="de_DE el_GR en es_ES fr_FR it_IT ja_JP ko_KR nl_NL pt_PT ru_RU tr_TR zh_CN zh_HK zh_TW"

XGETTEXT=/usr/bin/xgettext
MSGMERGE=/usr/bin/msgmerge

echo -n "Make ${APPNAME}.pot  "
if [ ! -e $POTFILES ] ; then
	echo "$POTFILES not found"
	exit 1
fi

$XGETTEXT --default-domain=${APPNAME} --directory=${SRCROOT} \
		--add-comments --keyword=_ --keyword=N_ --files-from=$POTFILES
if [ $? -ne 0 ]; then
	echo "xgettext error"
	exit 1
fi

if [ ! -f ${APPNAME}.po ]; then
	echo "No such file: ${APPNAME}.po"
	exit 1
fi

rm -f ${APPNAME}.pot && mv ${APPNAME}.po ${APPNAME}.pot
echo "done"

for LANG in $ALL_LINGUAS; do 
	echo "$LANG : "

	if [ ! -e $LANG.po ] ; then
		sed 's/CHARSET/UTF-8/g' ${APPNAME}.pot > ${LANG}.po
		echo "${LANG}.po created"
	else
		if $MSGMERGE ${LANG}.po ${APPNAME}.pot -o ${LANG}.new.po ; then
			if cmp ${LANG}.po ${LANG}.new.po > /dev/null 2>&1; then
				rm -f ${LANG}.new.po
			else
				if mv -f ${LANG}.new.po ${LANG}.po; then
					echo ""	
				else
					echo "msgmerge for $LANG.po failed: cannot move $LANG.new.po to $LANG.po" 1>&2
					rm -f ${LANG}.new.po
					exit 1
				fi
			fi
		else
			echo "msgmerge for $LANG failed!"
			rm -f ${LANG}.new.po
		fi
	fi
	echo ""
done

