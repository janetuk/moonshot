#!/usr/bin/python

'''A script to buildMoonshot  potentially using a schroot for install testing.
'''

from contextlib import contextmanager
import os, subprocess, exceptions
import re
import sys
from optparse import OptionParser
from shutil import copy



# These variables can be overridden by options. If packages is not
# set, then it is read from the source_packages file
packages = []  # Set of packages to build
prefix = "/usr/local/moonshot"
root_command = "fakeroot"

schroot_command = ""

class CommandError(exceptions.StandardError):
    pass

class Schroot(object):
    '''Represents a schroot used for building moonshot.'''

    def __init__(self, name):
        '''Initialize a new schroot option from the named
        schroot. Unless the named schroot starts with session:, then a
        new session schroot is created.'''
        if not name.startswith('session:'):
            self.name = command_output(('schroot', '-b',
                                        '-c', name))
            self.end_session = True
        else:
            self.name = name
            self.end_session = False

    def __del__(self):
        if self.end_session:
            try:
                run_cmd(('schroot', '-e', '-c', self.name))
            except CommandError: pass

@contextmanager
def current_directory(dir):
    "Change the current directory as a context manager; when the context exits, return."
    cwd = os.getcwd()
    os.chdir(dir)
    yield
    os.chdir(cwd)


def run_cmd(args, **kwords):
    rcode =  subprocess.call( args, **kwords)
    if rcode <> 0:
        raise CommandError(args)

def command_output(args) :
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    output = p.communicate()
    output = output[0]
    if p.returncode != 0:
        raise CommandError(args)
    return output.strip()

def build(package):
    with current_directory(package):
        run_cmd(('autoreconf', '-i', '-f'))
        configure_command = [
                                      './configure'] + configure_opts
        if len(schroot_command) > 0:
            configure_command = [schroot_command , "--"] \
                + configure_command
        print ' '.join(configure_command)
        sys.stdout.flush()
        run_cmd(configure_command, shell=False)
        if dist:
            try: os.mkdir('doc/api')
            except: pass
            run_cmd(root_command +' make dist-gzip', shell=True)
            run_cmd('cp *.tar.gz ' +dist_dir, shell=True)
        run_cmd(schroot_command + ' make', shell=True)

def make_install(package):
    with current_directory(package):
        install_command = root_command + " make install"
        print install_command
        sys.stdout.flush()
        run_cmd(install_command, shell=True)
        

def read_packages():
    '''Read in the packages file from source_packages
    '''
    try: pf = file("source_packages")
    except IOError:
        print "Error: source_packages file not found"
        exit(1)
    def is_comment(line):
        if re.match("^\\s*#", line): return False
        if "#" in line: raise ValueError(
            "Source package line contains a comment but not at beginning")
        return True
    return map(lambda(x): x.rstrip(),
        filter(is_comment, pf.readlines()))


# main program
opt = OptionParser()
opt.add_option('--prefix',
               dest="prefix", default=prefix,
               help="Set the prefix under which packages are built and"
               + "installed")
opt.add_option('-c', '--configure-opt', dest="configure_opts",
               action="append",
               help="Specify an option to pass to configure")
opt.add_option('-r', '--root-cmd', dest="root_command",
               default=root_command,
               help="Specify command to gain root for make install")
opt.add_option('-s', '--schroot',
               dest="schroot",
               help="Specify name of schroot to use for build;"
               "implicitly sets root_command")
opt.add_option( '--dist', action='store_true',
                default=False, dest='dist',
                help = 'make dist-gzip in addition to the build'
                )
opt.add_option('--tar-file',
               dest='tar_file',
               help = 'Tar up resulting distributions in given tar file',
               default = None)
opt.usage = "%prog [options] [packages]"
(options, packages) = opt.parse_args()
prefix = options.prefix
root_command = options.root_command
dist = options.dist
configure_opts = ['--prefix', prefix,
                  "LDFLAGS='-Wl,-L"+prefix+"/lib -Wl,-L/usr/lib/freeradius"
                  + " -Wl,-rpath="+prefix+"/lib'",
                  'CPPFLAGS="-I '+prefix+'/include"',
                  '--with-system-libtool', '--with-system-libltdl',
                  '--enable-tls', '--with-gssapi='+prefix,
                  "--with-xmltooling="+prefix, 
                  ]
if options.configure_opts is not None: 
    configure_opts.extend(options.configure_opts)
tar_file = options.tar_file
if tar_file is not None: dist = True

our_schroot = None
if options.schroot is not None:
    our_schroot = Schroot(options.schroot)
    schroot_command = "schroot -r -c " + our_schroot.name
    root_command = schroot_command + " -u root"

all_packages = read_packages()
if len(packages) == 0: packages = all_packages

os.umask(022)
if dist:
    try:
        os.mkdir('distributions')
    except: pass
    dist_dir = os.path.join(os.getcwd(), 'distributions')

try:
    for p in all_packages:
        if p in packages: build(p)
        if packages[-1] == p : break
        make_install(p)
    if tar_file is not None:
        with current_directory(dist_dir):
            run_cmd(['tar', '-cf', tar_file,
                     '.'])
except CommandError as c:
    print "Error:" + str(c.args)
    our_schroot = None
    exit(1)
finally: del our_schroot
