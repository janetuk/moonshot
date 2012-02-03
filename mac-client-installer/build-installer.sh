#!/bin/sh

#  build-installer.sh
#  
#  Copyright (c) 2012, JANET(UK)

cd ~/moonshot/mac-client-installer
pwd
echo "    *  Put the jhbuild config file in the correct place"
cp ./.jhbuildrc-custom ~/
echo "    *  Remove old files and directories"
rm *.dmg
rm *.pkg
rm -Rf moonshot
rm -Rf moonshot-ui
rm -Rf sasl
echo "Done"

echo "    *  Bootstrap jhbuild"
jhbuild bootstrap --ignore-system
pwd
echo "Done preparing"

echo "    *  build moonshot in jhbuild shell"
cd ../moonshot 
pwd
jhbuild run ./autogen.sh 
jhbuild run ./configure --enable-acceptor=no --with-krb5=$HOME//moonshot/mac-client-installer/krb/usr/local  
jhbuild run make && make install DESTDIR=$HOME/moonshot/mac-client-installer/moonshot
cd ~/moonshot/mac-client-installer
pwd
echo "Done"

echo "    *  The first time this script is run the following errors may be generated: "
echo "    *  ** Error during phase build of cyrus-sasl: ########## Error running make   *** [39/41]"
echo "    *  choose  [4] Start shell"
echo "      $ ./configure --prefix=/usr/local --with-gss_impl=mit"
echo "      $ exit "
echo "    *  choose [1] Rerun phase build"
echo
echo "    *  build cyrus-sasl using jhbuild"
jhbuild build cyrus-sasl
echo "Done"

echo "    *  Fix up the cyrus-sasl links"
mkdir -p sasl/usr/lib
cd sasl/usr/lib && ln -fs   ../local/lib/sasl2 
cd ~/moonshot/mac-client-installer
pwd
echo "Done"

#
# ToDo: Remove these lines when the Bug is fixed and the files referenced in the module
#       sets can be downloaded succesfully
echo "    *  Prepare to build moonshot-ui using jhbuild
echo "    *  We need to get the sources for the tango modules as the versions on the freedesktop.org download page are broken
echo "    *  see https://bugs.freedesktop.org/show_bug.cgi?id=45526
curl  -L http://pkgs.fedoraproject.org/repo/pkgs/tango-icon-theme/tango-icon-theme-0.8.90.tar.gz/0795895d2f20eddcbd2bffe94ed431a6/tango-icon-theme-0.8.90.tar.gz -o ~/gtk/source/pkgs/tango-icon-theme-0.8.90.tar.gz
curl  -L http://pkgs.fedoraproject.org/repo/pkgs/icon-naming-utils/icon-naming-utils-0.8.90.tar.gz/2c5c7a418e5eb3268f65e21993277fba/icon-naming-utils-0.8.90.tar.gz -o ~/gtk/source/pkgs/icon-naming-utils-0.8.90.tar.gz
curl  -L http://pkgs.fedoraproject.org/repo/pkgs/tango-icon-theme-extras/tango-icon-theme-extras-0.1.0.tar.gz/caaceaec7b61f1cbda0db9842f9db281/tango-icon-theme-extras-0.1.0.tar.gz -o ~/gtk/source/pkgs/tango-icon-theme-extras-0.1.0.tar.gz 

echo "    *  The first time this script is run the following errors may be generated: "
echo "    *  *** Error during phase configure of gtk-mac-bundler: ########## Error running ./configure --prefix /Users/pete/gtk/inst --libdir '/Users/pete/gtk/inst/lib'    *** "
echo "    *  choose [2] Ignore error and continue"
echo "    *"
echo "    *  *** Error during phase build of perl-xml-parser: ########## Error running make LD_RUN_PATH= *** [6/37]"
echo "    *  choose  [4] Start shell"
echo "    *    $ git apply ~/moonshot/mac-client-installer/0001-Remove-arch-ppc-flags.patch "
echo "    *    $ make"
echo "    *    $ exit "
echo "    *  choose [2] Ignore error and continue"
echo "    *"
echo "    *  *** Error during phase configure of gtk-mac-bundler: ########## Error running ./configure --prefix /Users/pete/gtk/inst --libdir '/Users/pete/gtk/inst/lib'    *** [37/38]"
echo "    *  choose [2] Ignore error and continue"
echo "    *"
echo "    *  Now we can build moonshot-ui"
jhbuild build moonshot-ui
echo "Done"
echo

echo "    *  Make moonshot-ui app bundle in jhbuild shell"
cd ~/gtk/source/moonshot-ui/ &&  jhbuild run make app-bundle 
echo "Done"

echo "    *  Make the libmoonshot files in the correct directory for the installer"
jhbuild run ./configure && make && make install DESTDIR=$HOME/moonshot/mac-client-installer/moonshot-ui
cd ~/moonshot/mac-client-installer
pwd
echo "Done"

echo "    *  Ensure the permissions are correct for the files to be installed"
sudo chown -R root:admin sasl krb moonshot moonshot-ui
sudo chmod -R g+w sasl krb moonshot moonshot-ui
echo "Done"

echo "    *  Put the DBus Property list in the moonshot-ui tree for the installer with the correct permissions"
cp org.freedesktop.dbus-session.plist moonshot-ui/
sudo chown -R root:admin moonshot-ui/org.freedesktop.dbus-session.plist

echo "    *  Create the installer package"
/Developer/usr/bin/packagemaker --doc Moonshot\ Client\ Software.pmdoc \
--version 0.1 --filter "/.DS_Store"  --root-volume-only \
--domain system --verbose --no-relocate -l "/" --target 10.5 \
--id ja.net.moonshotClientSoftware  --out Moonshot\ Client\ Software.pkg

echo "    *  Create and mount a disk image"
hdiutil create -size 20m -fs HFS+ -volname "Moonshot Client Software" temp.dmg 
hdiutil attach temp.dmg 

echo "    *  Copy the package and the READMEs"
cp -R Moonshot\ Client\ Software.pkg /Volumes/Moonshot\ Client\ Software/ 
# TODO we need some readmes for the Mac instalatiom
#cp -R resources/*  /Volumes/Moonshot\ Client\ Software/ 

echo "    *  Get rid of hidden files and folders that we don't need"
sudo rm -rf /Volumes/Moonshot\ Client\ Software/.fseventsd/ 
sudo rm -rf /Volumes/Moonshot\ Client\ Software/.Trashes/ 
sudo find /Volumes/Moonshot\ Client\ Software -name '.*' -type f -delete

echo "    *  Unmount the image"
hdiutil detach /Volumes/Moonshot\ Client\ Software 

echo "    *  Convert the disk image to read-only"
hdiutil convert temp.dmg -format UDZO -o moonshotclientsoftware.dmg 
#rm temp.dmg
echo "All Done"
