import boto3
import json
import logging
import os
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

        current_secret = get_current_secret(client, secret_arn)
        if not ('accessKey' in current_secret and 'secretKey' in current_secret):
            logger.error('secret must be key/value pairs including, values for accessKey and secretKey')
            raise KeyError
        logger.info(f'tioUsername: {current_secret["tioUsername"]}')

        # generate new keys (warning: invalidates the existing key)
        response = generate_tio_keys(current_secret)
        if response.status == 200:
            new_key_pair = json.loads(response.data)
            current_secret.update(new_key_pair)
            secret_string = json.dumps(current_secret)
            client.put_secret_value(SecretId=secret_arn, SecretString=secret_string)
        else:
            logger.error(f'unable to generate keys [{response.status}]: secret not updated: {response.status}')


def generate_tio_keys(current_secret: dict):
    """Use the existing key pair to generate and return a new key pair"""
    headers = {
        'X-ApiKeys': 'accessKey={accessKey};secretKey={secretKey}'.format(**current_secret),
        'Accept': 'application/json'
    }
    user_id = None
    http = urllib3.PoolManager()
    resp = http.request("GET", "https://cloud.tenable.com/users", headers=headers)
    logger.info(f'get user list returns {resp.status}')
    if resp.status == 200:
        users = json.loads(resp.data).get('users', [])
        for user in users:
            logger.info(f'account user is {user["username"]} vs {current_secret["tioUsername"]}')
            if user['username'] == current_secret['tioUsername']:
                user_id = user['id']
                break
    if user_id is not None:
        logger.info(f'user id is {user_id}')
        resp = http.request(
            "PUT", f"https://cloud.tenable.com/users/{user_id}/keys", headers=headers
        )
        logger.info(f'generate status is {resp.status}')
        return resp
    else:
        logger.error(f'account not found: <{current_secret.get("tioUsername")}>')
        raise LookupError(f'account not found: <{current_secret.get("tioUsername")}>')


def get_current_secret(secrets_client, secret_arn):
    try:
        secret = secrets_client.get_secret_value(SecretId=secret_arn)
        secret_string = secret['SecretString']
    except ClientError as e:
        logger.error(f'error getting secret: {e.response["Error"]["Code"]}')
        raise e
    except KeyError as e:
        logger.error(f'{repr(e)}: SecretString not in secret')
        raise e

    return json.loads(secret_string)
