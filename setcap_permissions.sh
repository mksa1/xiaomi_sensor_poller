#!/bin/sh

sudo setcap 'cap_net_raw,cap_net_admin+eip' `readlink -f \`which python3\``
