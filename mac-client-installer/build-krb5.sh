#!/bin/sh

#  build-krb5.sh
#  
#
#  Created by pete on 02/02/2012.
#  Copyright (c) 2012 __MyCompanyName__. All rights reserved.


export CFLAGS="-arch i386"
./configure --prefix=/usr/local
make
make install DESTDIR=$HOME/moonshot/mac-client-installer/krb

