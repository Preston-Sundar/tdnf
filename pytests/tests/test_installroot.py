#
# Copyright (C) 2021 VMware, Inc. All Rights Reserved.
#
# Licensed under the GNU General Public License v2 (the "License");
# you may not use this file except in compliance with the License. The terms
# of the License are located in the COPYING file of this distribution.
#
#   Author: Oliver Kurth <okurth@vmware.com>

import os
import shutil
import errno
import pytest

INSTALLROOT='/root/installroot'
REPOFILENAME='photon-test.repo'

REPODIR='/root/yum.repos.d'
REPONAME='reposdir-test'

@pytest.fixture(scope='function', autouse=True)
def setup_test(utils):
    yield
    teardown_test(utils)

def teardown_test(utils):
    if os.path.isdir(INSTALLROOT):
        shutil.rmtree(INSTALLROOT)
    pass

# helper to create directory tree without complains when it exists:
def makedirs(d):
    try:
        os.makedirs(d)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

def install_root(utils, no_reposd=False):
    makedirs(INSTALLROOT)
    makedirs(os.path.join(INSTALLROOT, 'etc/tdnf'))
    conffile = os.path.join(utils.config['repo_path'], 'tdnf.conf')

    # remove special settings for repodir and cachedir
    with open(conffile, 'r') as fin:
        with open(os.path.join(INSTALLROOT, 'etc/tdnf', 'tdnf.conf'), 'w') as fout:
            for line in fin:
                if not line.startswith('repodir') and \
                   not line.startswith('cachedir'):
                    fout.write(line)

    if not no_reposd:
        makedirs(os.path.join(INSTALLROOT, 'etc/yum.repos.d'))
        repofile = os.path.join(utils.config['repo_path'], "yum.repos.d", REPOFILENAME)
        shutil.copyfile(repofile, os.path.join(INSTALLROOT, 'etc/yum.repos.d', REPOFILENAME))
    makedirs(os.path.join(INSTALLROOT, 'var/cache/tdnf'))
    utils.run(['rpm', '--root', INSTALLROOT, '--initdb'])

# local version of check_package with install root
def check_package(utils, package, installroot=INSTALLROOT, version=None):
    """ Check if a package exists """
    ret = utils.run([ 'tdnf',
                     '--installroot', installroot,
                     '--releasever=4.0', 
                     'list', package ])
    for line in ret['stdout']:
        if package in line and '@System' in line:
            if version == None or version in line:
                return True
    return False

def erase_package(utils, pkgname, installroot=INSTALLROOT, pkgversion=None):
    if pkgversion:
        pkg = pkgname + '-' + pkgversion
    else:
        pkg = pkgname
    utils.run([ 'tdnf',
                '--installroot', installroot,
                '--releasever=4.0', 
                'erase', '-y', pkg ])
    assert(check_package(utils, pkgname) == False)

def test_install(utils):
    install_root(utils)
    pkgname = utils.config["mulversion_pkgname"]
    erase_package(utils, pkgname)

    ret = utils.run(['tdnf', 'install',
                     '-y', '--nogpgcheck',
                     '--installroot', INSTALLROOT,
                     '--releasever=4.0', pkgname ], noconfig=True)
    assert(ret['retval'] == 0)
    assert(check_package(utils, pkgname))

    shutil.rmtree(INSTALLROOT)

def test_makecache(utils):
    install_root(utils)
    ret = utils.run(['tdnf', 'makecache',
                     '-y', '--nogpgcheck',
                     '--installroot', INSTALLROOT,
                     '--releasever=4.0' ], noconfig=True)
    assert(ret['retval'] == 0)
    assert(os.path.isdir(os.path.join(INSTALLROOT, 'var/cache/tdnf', 'photon-test')))

    shutil.rmtree(INSTALLROOT)

def create_repoconf(filename, baseurl, name):
    templ = """
[{name}]
name=Test Repo
baseurl={baseurl}
enabled=1
gpgcheck=0
metadata_expire=86400
ui_repoid_vars=basearch
"""
    with open(filename, "w") as f:
        f.write(templ.format(name=name, baseurl=baseurl))

# --setopt=reposdir overrides any dir in install root
def test_setopt_reposdir_with_installroot(utils):
    install_root(utils)
    makedirs(REPODIR)
    create_repoconf(os.path.join(REPODIR, REPOFILENAME),
                    "http://foo.bar.com/packages",
                    REPONAME)
    ret = utils.run(['tdnf',
                     '--installroot', INSTALLROOT,
                     '--releasever=4.0',
                     '--setopt=reposdir={}'.format(REPODIR),
                     'repolist'])
    assert(REPONAME in "\n".join(ret['stdout']))

    shutil.rmtree(INSTALLROOT)

