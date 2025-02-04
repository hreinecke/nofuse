#!/usr/bin/python3

import os
import sys

def nvmet_iter(path):
    with os.scandir(path) as p:
        for entry in p:
            if not entry.name.startswith('.'):
                attr = None
                name = f'{path}/{entry.name}'
                if entry.is_dir(follow_symlinks=False):
                    nvmet_iter(name)
                elif entry.is_symlink():
                    try:
                        attr = os.readlink(name)
                    except:
                        attr = None
                else:
                    try:
                        with open(name) as f:
                            attr = f.read()
                    except:
                        attr = None
                if attr:
                    print(f'{name.lstrip("./")}: {attr.strip()}')

if not sys.argv[1]:
    raise NameError
os.chdir(sys.argv[1])
nvmet_iter('.')
