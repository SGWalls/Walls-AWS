import base64
import gzip
import json
import os
import socket

# CONFIGURE VIA ENVIRONMENT VARIABLES
SYSLOG_HOST = os.getenv('SYSLOG_HOST')  # e.g., "192.168.1.100"
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', 514))


def send_syslog(message):
    syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        syslog_socket.connect((SYSLOG_HOST, SYSLOG_PORT))
        syslog_socket.sendall(message.encode('utf-8'))
    # catch timeout exception
    except TimeoutError as e:
        print(f"Connection timed out: {str(e)}")
        # Handle the timeout as needed
    except socket.error as e:
        print(f"Socket error occurred: {str(e)}")
        # Handle other socket errors
    finally:
        syslog_socket.close()

def build_syslog_message(log_event):
    hostname = os.getenv("SYSLOG_HOSTNAME", "aws-rds")
    appname = "cloudwatch"
    msg = log_event['message'].strip().replace('\n', ' ')
    return f"<134>1 - {hostname} {appname} - - - {msg}"

def lambda_handler(event, context):
    cw_data = event['awslogs']['data']
    compressed_payload = base64.b64decode(cw_data)
    uncompressed_payload = gzip.decompress(compressed_payload).decode('utf-8')
    log_events = json.loads(uncompressed_payload)

    for log_event in log_events['logEvents']:
        syslog_msg = build_syslog_message(log_event)
        send_syslog(syslog_msg)

    return {
        'statusCode': 200,
        'body': json.dumps('Logs forwarded to LogRhythm')
    }
