#!/bin/bash

# author        Oliver Blaser
# date          24.03.2025
# copyright     GPL-3.0 - Copyright (c) 2025 Oliver Blaser

prjName="lsip"
prjDisplayName="lsip"
prjBinName=$prjName
prjDirName=$prjName
repoDirName=$prjName
copyrightYear=$(date +%Y)

versionstr=$(head -n 1 dep_vstr.txt)
versionstrDeb=$(echo "$versionstr" | tr - "~") # convert semver pre-release delimiter to debian compatible char

function ptintTitle()
{
    if [ "$2" = "" ]
    then
        echo "  --=====#   $1   #=====--"
    else
        echo -e "\033[3$2m  --=====#   \033[9$2m$1\033[3$2m   #=====--\033[39m"
    fi
}

# pass output filename as argument
function writeReadmeFile()
{
    echo ""                                 > $1
    echo "${prjDisplayName} v${versionstr}" >> $1
    echo ""                                 >> $1
    echo "GNU GPLv3 - Copyright (c) ${copyrightYear} Oliver Blaser" >> $1
    echo ""                                 >> $1
    echo "https://github.com/oblaser/${repoDirName}" >> $1
}
