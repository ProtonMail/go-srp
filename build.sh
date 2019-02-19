#!/bin/bash

SCRIPT_LOCATION=$(cd $(dirname $0);echo $PWD)

OUTPUT_PATH="dist"
ANDROID_OUT=${OUTPUT_PATH}/"Android"
IOS_OUT=${OUTPUT_PATH}/"iOS"

printf "\e[0;32mStart Building iOS framework .. Location: ${IOS_OUT} \033[0m\n\n"

gomobile bind -target ios -ldflags="-s -w -X srp.Version=$(git describe --always --long --dirty)" -o ${IOS_OUT}/Srp.framework 

printf "\e[0;32mStart Building Android lib .. Location: ${ANDROID_OUT} \033[0m\n\n"

gomobile bind -target android -ldflags="-s -w" -o ${ANDROID_OUT}/srp.aar

printf "\e[0;32mAll Done. \033[0m\n\n"


