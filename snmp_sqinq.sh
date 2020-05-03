#!/bin/bash

# configuration

TARGETIP=192.168.0.4
PUBLIC=public
OPTIONS='-v2c -On -Ln'
TOOL=snmpset

# description:
#      .          scalar            . .value. .port. .direction. .classifiervlan.
# oid: 1.3.6.1.4.1.35265.54.1.1.2.1.1   .5      .1       .2            .60

echo -e "\e[31megress permit\e[0m"
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.2.60 i 5 # raw status 5 (create and wait)
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.3.1.2.60 i 3 # action
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.4.1.2.60 i 0 # action vlan
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.2.60 i 1 # raw status 1 (active)

echo -e "\e[31megress deny\e[0m"
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.2.61 i 5
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.3.1.2.61 i 4
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.4.1.2.61 i 0
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.2.61 i 1

echo -e "\e[31megress add\e[0m"
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.2.62 i 5
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.3.1.2.62 i 2
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.4.1.2.62 i 10
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.2.62 i 1

echo -e "\e[31megress override\e[0m"
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.2.63 i 5
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.3.1.2.63 i 1
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.4.1.2.63 i 10
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.2.63 i 1

echo -e "\e[31mingress permit\e[0m"
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.1.64 i 5
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.3.1.1.64 i 3
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.4.1.1.64 i 0
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.1.64 i 1

echo -e "\e[31mingress deny\e[0m"
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.1.65 i 5
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.3.1.1.65 i 4
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.4.1.1.65 i 0
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.1.65 i 1

echo -e "\e[31mingress add\e[0m"
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.1.66 i 5
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.3.1.1.66 i 2
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.4.1.1.66 i 10
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.1.66 i 1

echo -e "\e[31mingress override\e[0m"
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.1.67 i 5
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.3.1.1.67 i 1
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.4.1.1.67 i 10
$TOOL $OPTIONS -c $PUBLIC $TARGETIP 1.3.6.1.4.1.35265.54.1.1.2.1.1.5.1.1.67 i 1