from urllib import request
import json
import boto3

def lookup_service_url(serviceName):
    return next((item for item in service_list if item['service'] == serviceName), {}).get('url', None)

def dict_search(dict_list, search_key, search_value):
    response = [item for item in dict_list if item.get(search_key) == search_value]
    if response:
        return response

def action_filter(action_list, property_filter):
    # for action in action_list:
    #     annotation_config = action['Annotations']
    #     props = annotation_config.get('Properties', {})
    #     if props[property_filter] == True:
    #         print(action)
    response = [action for action in action_list if action['Annotations']['Properties'][property_filter] == True]
    if response:
        return response

service_list = request.urlopen("https://servicereference.us-east-1.amazonaws.com/")
service_list = json.loads(service_list.read())

while True:
    service_lookup = input("Which service would you like to view? ")
    result = lookup_service_url(service_lookup)
    if result is not None:
        print(result)
        break
    else:
        print("Service not found. Please try again.")
# service_lookup = input("Which service would you like to view? ")
# result = lookup_service_url(service_lookup)

# result = next((item for item in service_list if item['service'] == service_lookup), None)

service_reference_list = request.urlopen(result)
service_reference_list = json.loads(service_reference_list.read())
service_action_list = service_reference_list['Actions']



# Most efficient for returning all matches
# results = [item for item in service_list if item['service'] == 'acm']
annotation_filter = input("Any properties for filter? ")

services_actions_inscope = action_filter(service_action_list, annotation_filter)

print(services_actions_inscope)