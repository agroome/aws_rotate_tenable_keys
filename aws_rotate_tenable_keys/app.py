import boto3
import json
import logging
import urllib3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info(f'Step is {event.get("Step")}')
    logger.info(f'SecretId is {event.get("SecretId")}')

    if event.get('Step') == 'createSecret':
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager')

        secret_arn = event.get('SecretId')

        current_keys = get_current_keys(client, secret_arn)
        if not ('accessKey' in current_keys and 'secretKey' in current_keys):
            logger.error('secret must be key/value pairs including, values for accessKey and secretKey')
            raise KeyError

        # generate new keys (warning: invalidates the existing key)
        response = generate_tio_keys(current_keys)
        if response.status == 200:
            new_key_pair = json.loads(response.data)
            # save the new key back to the secretsmanager
            secret_string = json.dumps(new_key_pair)
            response = client.put_secret_value(SecretId=secret_arn, SecretString=secret_string)
        else:
            logger.error(f'generate keys status: {response.status}')


def generate_tio_keys(key_pair: dict):
    """Use the existing key pair to generate and return a new key pair"""
    headers = {
        'X-ApiKeys': 'accessKey={accessKey};secretKey={secretKey}'.format(**key_pair),
        'Accept': 'application/json'
    }
    http = urllib3.PoolManager()
    resp = http.request(
        "PUT", "https://cloud.tenable.com/users/2/keys",
        headers=headers
    )
    return resp


def get_current_keys(secrets_client, secret_arn):
    try:
        secret = secrets_client.get_secret_value(SecretId=secret_arn)
        secret_string = secret['SecretString']
    except ClientError as e:
        logger.error(f'error getting secret: {e.response["Error"]["Code"]}')
        raise e
    except KeyError as e:
        logger.error(f'{e.response["Error"]["Code"]}: SecretString not in secret')
        raise e

    return json.loads(secret_string)
