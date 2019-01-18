#!/bin/bash

SCRIPT_LOCATION=$(cd $(dirname $0);echo $PWD)

OUTPUT_PATH="dist"
ANDROID_OUT=${OUTPUT_PATH}/"Android"
IOS_OUT=${OUTPUT_PATH}/"iOS"

# CHECK="${1-0}"
# if [ ${CHECK} -eq "1" ]; then
printf "\e[0;32mStart Building iOS framework .. Location: ${IOS_OUT} \033[0m\n\n"

gomobile bind -target ios -ldflags="-s -w -X srp.Version=$(git describe --always --long --dirty)" -o ${IOS_OUT}/Srp.framework 

#for vpn 
#gomobile bind -target ios -o ${IOS_OUT}/Srp_vpn.framework -tags openpgp -ldflags="-s -w"

printf "\e[0;32mStart Building Android lib .. Location: ${ANDROID_OUT} \033[0m\n\n"

gomobile bind -target android -ldflags="-s -w" -o ${ANDROID_OUT}/srp.aar

cp -rf ${IOS_OUT}/Srp.framework /Users/Yanfeng/Documents/ProtonMailGit/protonmail_ios/ProtonMail/

printf "\e[0;32mAll Done. \033[0m\n\n"


