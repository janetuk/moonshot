#!/bin/sh

#  build-installer.sh
#  
#
#  Created by pete on 02/01/2012.
#  Copyright (c) 2011, JANET(UK)

#cp ./.jhbuildrc-custom ~

#cd ../moonshot && jhbuild run ./configure --enable-acceptor=no --with-krb5=$HOME/gtk/inst && make && make install DESTDIR=$HOME/moonshot/mac-client-installer/moonshot

#jhbuild build cyrus-sasl

#jhbuild build moonshot-ui

#cd ~/gtk/source/moonshot-ui/ &&  jhbuild run make app-bundle && jhbuild run make installer

hdiutil create -size 2m -fs HFS+ -volname "Moonshot Client Software" temp.dmg 

hdiutil attach temp.dmg 


# Copy the package and the READMEs
cp -R Moonshot\ Client\ Software.pkg /Volumes/Moonshot\ Client\ Software/ 
# Get rid of hidden files and folders that we don't need
cp -R resources/*  /Volumes/Moonshot\ Client\ Software/ 
sudo rm -rf /Volumes/Moonshot\ Client\ Software/.fseventsd/ 
sudo rm -rf /Volumes/Moonshot\ Client\ Software/.Trashes/ 
sudo find /Volumes/Moonshot\ Client\ Software -name '.*' -type f -delete

# Unmount the image
hdiutil detach /Volumes/Moonshot\ Client\ Software 

# Convert the disk image to read-only
hdiutil convert temp.dmg -format UDZO -o moonshotclientsoftware.dmg 
rm temp.dmg

