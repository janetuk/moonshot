#!/bin/sh

#  msbuild.sh
#  
#
#  Created by pete on 01/02/2012.
#  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
# build moonshot-ui using jhbuild
jhbuild buildone moonshot-ui

# make moonshot-ui app bundle in jhbuild shell
cd ~/gtk/source/moonshot-ui/ &&  jhbuild run make app-bundle 
pwd

cd ~/moonshot/mac-client-installer
rm -r /Applications/moonshot-ui.app/

