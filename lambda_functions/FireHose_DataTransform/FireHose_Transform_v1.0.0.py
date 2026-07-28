import json
import base64
import gzip
import zlib

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
        

def lambda_handler(event, context):
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
