#!/bin/bash
if test -z "$1" 
then
key="injector-key"
else
key="$1"
fi

if test -z "$2" 
then
executable="../injector"
else
executable="$2"
fi

/usr/bin/codesign --entitlements entitlement.xml --force --sign "$key" "$executable"