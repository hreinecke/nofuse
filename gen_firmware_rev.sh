#!/bin/bash

git show --no-abbrev-commit | \
	head -1 | cksum | cut -f 1 -d ' ' | base32 | \
	sed -n 's/\(.\{8\}\).*/static char firmware_rev[] = "\1";/p' > $1

