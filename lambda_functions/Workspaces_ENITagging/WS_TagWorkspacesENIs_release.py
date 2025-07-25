import json
import logging
import boto3
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("boto3").setLevel(logging.WARNING)
logging.getLogger("botocore").setLevel(logging.WARNING)

def lambda_handler(event, context):

    ec2 = boto3.resource('ec2')
  
    logger.info("Querying for EUC ENI id in event data.")
    try :
        eni_id = event['detail']['responseElements']['networkInterface']['networkInterfaceId']
        logger.info("ENI id found in event data: %s.", eni_id)
        
        # Get eni details
        logger.info("Generating ENI details.")
        euc_eni = ec2.NetworkInterface(eni_id)

        if "Created By Amazon Workspaces for AWS Account ID " not in euc_eni.description:
            logger.info("ENI description does not match Workspaces pattern, will not add tags.")
            return {
                'statusCode': 200
            }
        # Check for existing tag
        if any(tag.get('Key') == 'euc' and tag.get('Value') == 'workspaces' for tag in euc_eni.tag_set):
            logger.info("Found existing EUC tag on ENI, will not add again.")
            return {'statusCode': 200}

        euc_eni.create_tags(Tags=[{'Key': 'euc', 'Value': 'workspaces'}])
        logger.info(f"Successfully tagged ENI {eni_id} with euc=workspaces")
        
    except Exception as e :
        logger.error(e)
        logger.error("Unable to successfully update tags on ENI.")
        return {'statusCode': 500, 'error': str(e)}
    

    return {'statusCode': 200, 'message': 'ENI tagged successfully'}



