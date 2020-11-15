#!/bin/sh

# Define blueby_helper prefix path
BLUEBY_HELPER_PREFIX="lib/python3.7/site-packages/bluepy"

# Get full path to activated virtual environment
virtualenv=`python3 $HOME/.poetry/bin/poetry env list --full-path | grep Activated | cut -d " " -f 1`
path_bluepy_helper=`find $virtualenv -name bluepy-helper`

sudo setcap cap_net_raw+e  $path_bluepy_helper
sudo setcap cap_net_admin+eip  $path_bluepy_helper
