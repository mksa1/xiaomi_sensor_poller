"""Xiaomi passive BLE monitor integration."""
# Standard library imports
from datetime import datetime
import json
import logging
import logging.config
import time

# Third party imports
from collections import OrderedDict
from time import sleep
import paho.mqtt.client as mqtt

# Local imports
import xiaomi_poller.misensor as misensor
from xiaomi_poller.sensor_config import settings

from xiaomi_poller.const import (
    DEVICE_CLASS_BATTERY,
    DEVICE_CLASS_HUMIDITY,
    DEVICE_CLASS_TEMPERATURE,
)

# Logging configuration
logging.config.fileConfig(fname="logging.conf", disable_existing_loggers=False)
_LOGGER = logging.getLogger()


# Initialize MQTT connection. Return MQTT client
def init_mqtt_connection(settings):
    mqtt_server = settings['host']
    mqtt_user = settings['username']
    mqtt_pass = settings['password']
    mqtt_port = settings['port']
    client = mqtt.Client()
    client.username_pw_set(mqtt_user, mqtt_pass)
    client.connect(mqtt_server, mqtt_port)
    return client


def process_data(scanner, mqtt_client):
    _LOGGER.debug("Started processing data at %s", datetime.utcnow())

    # Trigger update of sensors
    scanner.update_ble(datetime.utcnow())

    # Get current list of sensors
    sensors_by_mac = scanner.get_sensors()

    base_state_topic = settings['mqtt']['base_topic']

    # Loop through sensors and send Discovery Announcement
    for mac in sensors_by_mac:
        _LOGGER.debug("Discovery update - Processing for MAC %s ", mac)
        for sensor in sensors_by_mac[mac]:
            _LOGGER.debug("Discovery update - Processing sensor %s: ", sensor.name)
            state_topic = '{}/sensor/{}/state'.format(base_state_topic, sensor.name)
            discovery_topic = 'homeassistant/sensor/{}/{}/config'.format(sensor.name, sensor.device_class)
            data = sensor.device_state_attributes
            payload = OrderedDict()
            payload['name'] = "{} {}".format(sensor.sensor_name, sensor.device_class)
            payload['unique_id'] = "{}-{}".format(mac.lower().replace(":", ""), sensor.device_class)
            payload['unit_of_measurement'] = sensor.unit_of_measurement
            payload['device_class'] = sensor.device_class
            payload['state_topic'] = state_topic
            payload['value_template'] = "{{{{ value_json.{} }}}}".format(sensor.device_class)
            payload['device'] = {
                    'identifiers': ["MiSensor{}".format(mac.lower().replace(":", ""))],
                    'connections': [["mac", mac.lower()]],
                    'manufacturer': 'Xiaomi',
                    'name': sensor.sensor_name,
                    'model': "Xioami MI sensor {}".format(data['sensor type']),
            }
            _LOGGER.debug(
                "Discovery update - MQTT sending to topic: %s Payload: %s ",
                discovery_topic,
                payload,
            )
            (return_code, client_id) = mqtt_client.publish(discovery_topic, json.dumps(payload), 1, True)
            if (return_code > 0):
                _LOGGER.debug(
                        "MQTT send failed topic: %s Payload: %s Return code %s ClientID %2",
                        discovery_topic,
                        payload,
                        return_code,
                        client_id
                )

    # Loop through sensors and send State Update
    for mac in sensors_by_mac:
        _LOGGER.debug("State update - Processing for MAC %s ", mac)
        for sensor in sensors_by_mac[mac]:
            _LOGGER.debug("State update - Processing sensor %s: ", sensor.name)
            state_topic = '{}/sensor/{}/state'.format(base_state_topic, sensor.name)
            data = sensor.device_state_attributes
            _LOGGER.debug("Date received from BLE - %s: ", data)
            payload = ""
            if(sensor.device_class == DEVICE_CLASS_TEMPERATURE and 'mean' in data):
                payload = json.dumps({'temperature': data['mean']})
            elif (sensor.device_class == DEVICE_CLASS_HUMIDITY and 'mean' in data):
                payload = json.dumps({'humidity': data['mean']})
            elif (sensor.device_class == DEVICE_CLASS_BATTERY):
                # Battery level is kept in state
                payload = json.dumps({'battery': sensor.state})
            _LOGGER.debug(
                "MQTT state sending to topic: %s Payload: %s ",
                state_topic,
                payload,
            )
            if (payload != ""):
                (return_code, client_id) = mqtt_client.publish(topic=state_topic, payload=payload)
                if (return_code > 0):
                    _LOGGER.debug(
                        "MQTT send failed topic: %s Payload: %s Return code %s ClientID %2",
                        state_topic,
                        payload,
                        return_code,
                        client_id
                    )


def main():
    # Initialize scanner platform
    scanner = misensor.BLEScanner()

    # Setup passive scanner platform
    scanner.setup_platform(settings['sensor'])

    # Initialize MQTT client
    mqtt_client = init_mqtt_connection(settings['mqtt'])

    # Continually process BLE data
    update_interval = settings['sensor']['update_interval']
    while True:
        process_data(scanner, mqtt_client)
        sleep(update_interval - time.time() % update_interval)


if __name__ == "__main__":
    main()
