import boto3
import logging
from botocore.exceptions import ClientError
from retriever import validate_sso_token

logger = logging.getLogger('snslogging')
session = boto3.Session(profile_name='dev_fhdeapp',region_name='us-west-2')
validate_sso_token(session)
sns = session.client('sns')
pinpoint = session.client('pinpoint-sms-voice-v2')
phone_number='18159553476'

origination_num = pinpoint.describe_phone_numbers(Owner='SHARED')['PhoneNumbers']
print(origination_num)
# if origination_num:
#     try:
#         response = sns.publish(
#         PhoneNumber=phone_number,
#         Message='This is a Test',
#         MessageAttributes={
#                 'AWS.SNS.SMS.SMSType': {
#                     'DataType': 'String',
#                     'StringValue': 'Transactional'
#                     },
#                 'AWS.MM.SMS.OriginationNumber': {
#                     'DataType': 'String',
#                     'StringValue': origination_num['PhoneNumber']
#                 }
#             }
#         )
#         message_id = response["MessageId"]
#         logger.info("Published message to %s.", phone_number)
#     except ClientError:
#         logger.exception("Couldn't publish message to %s.", phone_number)
#         raise
#     else:
#         print(message_id)
# else:
#     print("no origination number in account")