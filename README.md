# Introduction
This project provides an Xiaomi sensor poller supporting Home Assistant's MQTT format. This includes auto discovery and continual metric updates.
This can as an example be deployed on a RaspBerry PI for a distributed collection of Xiaomi BLE advertisements.

# Credits
The project is based on code from https://github.com/custom-components/ble_monitor and https://github.com/home-assistant/core/tree/dev/homeassistant/components/miflora

# Supported devices
Overview
![Supported sensors](pictures/sensors.jpg)



# Setup instructions
Setup and dependency management is handled by Poetry. See https://python-poetry.org/ for an introduction

## Poetry installation:
Read https://python-poetry.org/docs/#installation for details on installation and update

In short do:
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -


## Poller setup
git clone https://github.com/mksa1981/xioami_sensor_poller.git

cd xioami_sensor_poller
poetry install

setcap_permissions.sh


## Configuration
Configuration is handled through DynaConf in settings.toml and .secrets.toml  
Copy .secrets.toml.sample to .secrets.toml and adjust mqtt password.
Logging is configured in logging.conf

# Running the poller

Running the poller:
poetry run sensorPoller



