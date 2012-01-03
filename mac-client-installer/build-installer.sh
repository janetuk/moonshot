#!/bin/sh

#  build-installer.sh
#  
#
#  Created by pete on 02/01/2012.
#  Copyright (c) 2011, JANET(UK)

cp ./.jhbuildrc-custom ~/

# build moonshot in jhbuild shell
cd ../moonshot && jhbuild run ./configure --enable-acceptor=no --with-krb5=$HOME/gtk/inst && make && make install DESTDIR=$HOME/moonshot/mac-client-installer/moonshot

# build cyrus-sasl using jhbuild
jhbuild build cyrus-sasl

# build moonshot-ui using jhbuild
jhbuild build moonshot-ui

# make moonshot-ui app bundle in jhbuild shell
cd ~/gtk/source/moonshot-ui/ &&  jhbuild run make app-bundle 
pwd

cd ~/moonshot/mac-client-installer
pwd
# fix up the cyrus-sasl links
mkdir -p sasl/usr/lib
cd sasl/usr/lib && ln -fs   ../local/lib/sasl2 
cd ~/moonshot/mac-client-installer
pwd

# Ensure the permissions are correct for the files to be installed
sudo chown -R root:admin sasl krb moonshot moonshot-ui
sudo chmod -R g+w sasl krb moonshot moonshot-ui

# create the installer package
/Developer/usr/bin/packagemaker --doc Moonshot\ Client\ Software.pmdoc \
--version 0.1 --filter "/.DS_Store"  --root-volume-only \
--domain system --verbose --no-relocate -l "/" --target 10.5 \
--id ja.net.moonshotClientSoftware  --out Moonshot\ Client\ Software.pkg

# create and mount a disk image
hdiutil create -size 20m -fs HFS+ -volname "Moonshot Client Software" temp.dmg 
hdiutil attach temp.dmg 

# Copy the package and the READMEs
cp -R Moonshot\ Client\ Software.pkg /Volumes/Moonshot\ Client\ Software/ 
# TODO we need some readmes for the Mac instalatiom
#cp -R resources/*  /Volumes/Moonshot\ Client\ Software/ 

# Get rid of hidden files and folders that we don't need
sudo rm -rf /Volumes/Moonshot\ Client\ Software/.fseventsd/ 
sudo rm -rf /Volumes/Moonshot\ Client\ Software/.Trashes/ 
sudo find /Volumes/Moonshot\ Client\ Software -name '.*' -type f -delete

# Unmount the image
hdiutil detach /Volumes/Moonshot\ Client\ Software 

# Convert the disk image to read-only
hdiutil convert temp.dmg -format UDZO -o moonshotclientsoftware.dmg 
rm temp.dmg

