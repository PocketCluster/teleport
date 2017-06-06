#!/usr/bin/env bash

echo "Remove local settings..."

rm -rf ${HOME}/.pocket ${HOME}/.tsh && mkdir -p ${HOME}/.pocket

TARGET_HOST=${1}
if [[ -z ${TARGET_HOST} ]]; then
    exit
fi

echo "Checking remote host connectivity..."
CONN_CHECK=$(ssh -q -o "BatchMode=yes" ${TARGET_HOST} "echo 2>&1" && echo "OK" || echo "NOPE" )
if [[ ${CONN_CHECK} == "NOPE" ]]; then
    echo "Unable to connect ${TARGET_HOST}"
    exit
fi

ssh ${TARGET_HOST} "rm -rf ~/temp/ && sudo -s rm -rf /root/temp/"