#!/usr/bin/env python3
import paho.mqtt.client as paho
import http.client, urllib
import argparse
import logging
import json
import os
import re
import signal
import sys

from json.decoder import JSONDecodeError

def signal_handler(signum, frame):
    if client.is_connected():
        publish_result = client.publish(args.mqtt_topic, payload = "offline", qos = 0, retain=False)
        publish_result.wait_for_publish()
        client.disconnect()
        client.loop_stop()
    logging.info("Exit - See you next time ;)")
    sys.exit()

def get_message_type(userdata, msg):
    message_type = find_element_in_topic(userdata.mqtt_topic, msg)
    logging.debug('message type: ' + str(message_type))
    if message_type in ('title', 'device', 'priority'):
        return None
    return message_type

def get_priority(message_type):
    if message_type == 'error':
        return 1
    elif message_type in ('alert', 'warning'):
        return 0
    elif message_type in ('notice'):
        return -2
    else:
        return -1

def find_element_in_topic(element, msg, default=None):
    m = re.search('(^' + element + '\/|\/' + element + '\/)([^\/]*)', msg.topic)
    if m:
        return m.group(2)
    else:
        return default


def split_topic(userdata, msg):
    title = find_element_in_topic('title', msg, userdata.mqtt_topic)
    device = find_element_in_topic('device', msg, None)
    return title, device

def get_reponse_error(response):
    body = response.read()
    try:
        bodyDict = json.loads(body)
        if "errors" in bodyDict:
            body = bodyDict["errors"][0]
    except:
        pass
    return body

def validate_pushover(args):
    conn = http.client.HTTPSConnection('api.pushover.net:443')
    conn.request('POST', '/1/users/validate.json',
        urllib.parse.urlencode({'token': args.pushover_app_token,
            'user': args.pushover_user_token}), { 'Content-type': 'application/x-www-form-urlencoded' })
    response = conn.getresponse()
    if response.status != 200:
        logging.error(get_reponse_error(response))
        exit()

def on_connect(client, userdata, flags, rc):
    topic = str(userdata.mqtt_topic).strip('/') + '/#'
    logging.info('Subscribed to topic: ' + topic)
    client.subscribe(topic,0)

def on_message(client, userdata, msg):
    logging.info('received message with topic'+msg.topic)

    """
    Get title (.../title/.*/), device (.../device/.*/)
    and priority (the word after your subscribing topic either error->1, alert or warning -> 0, notice -> -2 everything else -> -1)

    Priority Numbers meaning in Pushover:
    1   -> Push Message, with signal and the message is red in Pushover
    0   -> Push Message, with signal
    -1  -> Push Message no signal
    -2  -> No Push Message. Message only gets added into the Pushover app.
    """
    message_type = get_message_type(userdata, msg)
    title, device = split_topic(userdata, msg)
    priority = get_priority(message_type)

    """
    Message can now be a single string or a json to override, title, device and priority
    """

    msgData = msg.payload.decode('utf-8')
    try:
        dataDict = json.loads(msgData)
        logging.debug('json received ' + str(dataDict))
        message = dataDict['message']
        if 'title' in dataDict:
            title = dataDict['title']
        if 'device' in dataDict:
            device = dataDict['device']
        if 'priority' in dataDict:
            priority = dataDict['priority']
    except JSONDecodeError:
        """
        Message is a String
        """
        message = msgData

    body = {
            'token': userdata.pushover_app_token,
            'user': userdata.pushover_user_token,
            'priority': priority,
            'message': message,
            'title': title,
            'device': device,
            'html': userdata.pushover_html_parser
            }
    logging.debug(body)

    conn = http.client.HTTPSConnection('api.pushover.net:443')
    conn.request('POST', '/1/messages.json',
        urllib.parse.urlencode(body), { 'Content-type': 'application/x-www-form-urlencoded' })
    response = conn.getresponse()
    if response.status != 200:
        logging.error(get_reponse_error(response))

def get_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', help='Enable Debug mode', action='store_true', default=os.environ.get(key='MQTT2PUSHOVER_DEBUG', default=False), dest="debug")
    ap.add_argument('--mqtt-host', help='MQTT Host to connect to', default=os.environ.get(key='MQTT2PUSHOVER_MQTT_HOST', default='localhost'), dest='mqtt_host')
    ap.add_argument('--mqtt-port', help='MQTT port to connect to', type=int, default=os.environ.get(key='MQTT2PUSHOVER_MQTT_PORT', default='1883'), dest='mqtt_port')
    ap.add_argument('--mqtt-topic', help='MQTT Topic to listen to', required=False, default=os.environ.get(key='MQTT2PUSHOVER_MQTT_TOPIC', default='mqtt2pushover'), dest='mqtt_topic')
    ap.add_argument('--mqtt-user', help='MQTT user to connect to', required=False, default=os.environ.get(key='MQTT2PUSHOVER_MQTT_USER', default=None), dest='mqtt_user')
    ap.add_argument('--mqtt-password', help='MQTT password to connect to', required=False, default=os.environ.get(key='MQTT2PUSHOVER_MQTT_PASS', default=None), dest='mqtt_password')
    ap.add_argument('--app-token', help='Pushover APP Token', default=os.environ.get(key='MQTT2PUSHOVER_PUSHOVER_APP_TOKEN'), dest='pushover_app_token')
    ap.add_argument('--user-token', help='Pushover User Token', default=os.environ.get(key='MQTT2PUSHOVER_PUSHOVER_USER_TOKEN'), dest='pushover_user_token')
    ap.add_argument('--html', help='Enable HTML parsing', action='store_const', const=1, default=os.environ.get(key='MQTT2PUSHOVER_HTML_PARSER', default=0), dest="pushover_html_parser")

    args = ap.parse_args()
    return args

if __name__ == '__main__':
    args = get_args()
    loglevel = logging.INFO
    if args.debug:
        print("Debug mode enabled")
        loglevel = logging.DEBUG

    validate_pushover(args)

    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=loglevel)
    client = paho.Client()
    client.user_data_set(args)
    client.username_pw_set(args.mqtt_user, args.mqtt_password)
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(args.mqtt_host, args.mqtt_port, 60)
        client.publish(args.mqtt_topic, payload = "online", qos = 0, retain=False)
    except ConnectionRefusedError as e:
        sys.exit("MQTT Connection error: " + e.strerror)

    logging.info('Connected to MQTT Server successfully')

    signal.signal(signal.SIGINT, signal_handler)
    client.loop_forever()

