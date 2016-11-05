#!/usr/bin/env python

import os
import sys
import signal
from pwd import getpwuid
def owner(pid):
    for line in open('/proc/%d/status' % pid):
        if line.startswith('Uid:'):
            uid = int(line.split()[1])
            return getpwuid(uid).pw_name
def me():
    return getpwuid(os.getuid())[0]

for dirname in os.listdir('/proc'):
    if dirname == 'curproc':
        continue

    try:
        with open('/proc/{}/cmdline'.format(dirname), mode='rb') as fd:
            content = fd.read().decode().split('\x00')
	    pid = dirname 
    except Exception:
        continue

    for i in sys.argv[1:]:
        if i in content[0]:
	    if owner(int(pid)) == me():
                print('pid = ' + ''.join(pid))
                print('owner = ' + ''.join(owner(int(pid))))
                for j in content[0:]:
                    print(''.join(j))
                print('Killing with sigkill signal')
	        os.kill(int(pid), signal.SIGKILL)
