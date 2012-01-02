#!/bin/sh

#  build-installer.sh
#  
#
#  Created by pete on 02/01/2012.
#  Copyright (c) 2011, JANET(UK)

cp ./.jhbuildrc-custom ~

cd ../moonshot && jhbuild run ./configure --enable-acceptor=no --with-krb5=$HOME/gtk/inst && make && make install DESTDIR=$HOME/moonshot/mac-client-installer/moonshot

jhbuild build cyrus-sasl

jhbuild build moonshot-ui

cd ~/gtk/source/moonshot-ui/ &&  jhbuild run make app-bundle && jhbuild run make installer