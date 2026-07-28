import json
import base64
import gzip
import zlib
import os
import datetime
import codecs

event = {
    "records": [
        {
            "recordId": "0aef1e012g56w61d02g2sasw51j1k5s2e",
            "data": "H4sIACESpGYC/73VW2vbMBQA4L8i9Nx45+iuvRnPLWPeEkhWGGUEx1GCwbGN7aaU0v8+KS5dVvZQ2JwXIXMkHX26WE/04Po+37vVY+voR0I/xat4/TVdLuOblF4R2jzUrgsBtBKEVkyBkiFQNfubrrlvQ+x2kayvq+Yha/b9h2NbzEDtpLOYb1UBfMe2+NJjOXQuP4Quri5ngFgA28kctsWmyO1mlldVaNnfb/qiK9uhbOrrshpc1/s+dzSth1ni6qHLq7htfbZFU5XFI/05jp4efezU8omW25CFGwEgjNIGJSgUfvpMo9SASgpppdJaKzDGt7PAJFgBFrRkYRJD6ZdmyA9BiJqh5ZobBAAfe1m0kIKR85Uhf3URhMhAxCMtQhW1iTBiQMJonEhlOCOK+JGUPUv1WrWWxEmSLlZk/oU+X5F/1PEJdGekV+noGo2jDi+gE/9dZ3mEwkbIVYTG/KEVwtNQa/BA9J/oi+mJctINfMMdeScosYSjMhcQqkmEzJ9Ln/fNDkp/UC2cdpBIdgGcnvj+/YaOsEAMOHGJ62emxEnmywhtpDVRfub+H8N9AsIJt++4eOGZaE8vRuaOrgpT8NH592+rdZbeptl6Mc8+Jz/o8y8UTq9lFgcAAA=="
        }
    ]
}

dict1 = {
    "messageType": "DATA_MESSAGE",
    "owner": "123456789012",
    "logGroup": "testLogGroup",
    "logStream": "testLogStream",
    "subscriptionFilters": [
        "testFilter"
    ],
    "policyLevel": "0",
    "logEvents": [
        {
            "id": "01234567890123456789012345678901234567890123456789012345",
            "timestamp": 1510109207000,
            "message": "log message 1"
        },
        {
            "id": "01234567890123456789012345678901234567890123456789012345",
            "timestamp": 1510109208000,
            "message": "log message 2"
        }
    ]
}
# function to decompress gzipped data if encrypted and decode base64
def decompress_and_decode(data):
    try:
        # Decode base64
        decoded_data = base64.b64decode(data)
        #check if data is gzipped
        if decoded_data[:2] == b'\x1f\x8b':
            # Decompress gzipped data
            decompressed_data = gzip.decompress(decoded_data)
            return decompressed_data.decode('utf-8')
        else:
            return decoded_data.decode('utf-8')
    except (ValueError, zlib.error):
        return None

# function to encode to base64 and compress with gzip if compress flag is true
def encode_and_compress(data, compress=False):
    try:
        # Encode to base64
        if compress:
            # Compress string with gzip
            data = gzip.compress(data.encode('utf-8'))
            # compressed_data = gzip.compress(data)
        encoded_data = base64.b64encode(data)
        return encoded_data
    except (ValueError, zlib.error):
        return None

# function to format output for Firehose response.
def format_output(recordId,result,data):
    return {'recordId': recordId, 'result': result, 'data': data}

def multiline_json_dumps(json_list):
    result = []
    for json_object in json_list:
        # result += json.dumps(json_object) + "\n"
        result.append(json.dumps(json_object) + f'\n')
    result = ''.join(result)
    return result

def generate_dictionary(record,event):
    return {
        'messageType': record['messageType'],
        'owner': record['owner'],
        'logGroup': record['logGroup'],
        'logStream': record['logStream'],
        'subscriptionFilters': record['subscriptionFilters'],
        'policyLevel': record['policyLevel'],
        'logEvents': [event]
    }

def split_events(record):
    events = []
    events = [generate_dictionary(record,event) for event in record['logEvents']]
    return events
        

def handler(event, context):
    output = []

    for record in event['records']:
        print(record['recordId'])
        payload = json.loads(decompress_and_decode(record['data']))

        # Do custom processing on the payload here
        if len(payload['logEvents']) > 1:
            split_payload = split_events(payload)
            output_record = {
                'recordId': record['recordId'],
                'result': 'Ok',
                # 'data': base64.b64encode(multiline_json_dumps(split_payload).encode("utf-8")).decode("utf-8")
                'data': encode_and_compress(multiline_json_dumps(split_payload),compress=True)
            }
        else:
            output_record = {
                'recordId': record['recordId'],
                'result': 'Ok',
                'data': base64.b64encode(payload.encode("utf-8")).decode("utf-8")
            }                   
        output.append(output_record)

    print('Successfully processed {} records.'.format(len(event['records'])))

    return {'records': output}

# set filepath for output.
file_location = 'C:\\Users\\sgwalls\\Documents\\AWS_Projects\\exports\\FirehoseTransform'
# check path and create if not exists
if not os.path.exists(file_location):
    os.makedirs(file_location)
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
output_file = os.path.join(file_location, f'FirehoseTransform_{timestamp}.txt')
outfile = handler(event, context=None)
outfile['records'][0]['data'] = decompress_and_decode(outfile['records'][0]['data'])
# write to file.
with open(output_file, 'w') as f:
    f.write(codecs.decode(str(outfile['records'][0]['data']),"unicode_escape"))

