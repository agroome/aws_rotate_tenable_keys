import boto3
import configparser
from boto3_type_annotations.sts import Client as STSClient
from boto3_type_annotations.iam import Client as IAMClient
from pathlib import Path
from pprint import pprint


default_mfa_sn = 'arn:aws:iam::773284714180:mfa/andyg'
default_credentials_file = Path.home() / '.aws' / 'credentials'


def read_user_config(filename):
    config = configparser.ConfigParser()
    with open(filename) as fp:
        config.read_file(fp)
    return config


def print_config(config):
    for section in config.sections():
        print(f'[{section}]')
        for k, v in config[section].items():
            print(f'{k} = {v}')


def update_credentials(section, credentials, region='us-east-1', file=default_credentials_file):
    config = configparser.ConfigParser()
    with open(file) as fp:
        config.read_file(fp)

    config[section] = {
        'aws_access_key_id': credentials['AccessKeyId'],
        'aws_secret_access_key': credentials['SecretAccessKey'],
        'region': region
    }
    if 'SessionToken' in credentials:
        config[section].update({'aws_session_token': credentials['SessionToken']})

    with open(file, 'w') as fp:
        config.write(fp)


def update_mfa_credentials(profile, credentials, region='us-east-1', credentials_file=default_credentials_file):
    config = configparser.ConfigParser()
    with open(credentials_file) as fp:
        config.read_file(fp)

    config[profile] = {
        'aws_access_key_id': credentials['AccessKeyId'],
        'aws_secret_access_key': credentials['SecretAccessKey'],
        'aws_session_token': credentials['SessionToken'],
        'region': region
    }
    with open(credentials_file, 'w') as fp:
        config.write(fp)


def mfa_login(mfa_sn, token_code, duration_seconds=None, profile_name='mfa'):
    """Use the STS service to get a temporary session token and api keys."""
    print('getting session token...')
    client: STSClient = boto3.client('sts')
    response = client.get_session_token(
        SerialNumber=mfa_sn, TokenCode=token_code, DurationSeconds=duration_seconds
    )
    if 'Credentials' in response:
        credentials_file = Path.home() / '.aws' / 'credentials'
        update_mfa_credentials(profile_name, response['Credentials'])
        print('updated mfa credentials')
    else:
        print(response)


def get_user_mfa_device():
    client: IAMClient = boto3.client('iam')
    mfa_devices = client.list_mfa_devices()['MFADevices']
    if not mfa_devices:
        print('mfa not configured for this user')
    else:
        device = mfa_devices[0]
        return device


def do_login():
    device = get_user_mfa_device()
    print(f'username: {device["UserName"]}')
    print(f'device with arn: {device["SerialNumber"]}')

    mfa_sn = input(f'enter code: ')
    token_code = input(f'Token code: ')
    mfa_login(mfa_sn, token_code)


def rotate_access_keys():
    session = boto3.Session(profile_name='mfa')
    client: IAMClient = session.client('iam')
    new_keys = client.create_access_key(UserName='andyg')
    print("setting new credentials to [pending]")
    update_credentials(section='PENDING', credentials=new_keys['AccessKeyMetadata'])

    # test new credentials
    session = boto3.Session(profile_name='PENDING')
    client = session.client('iam')
    try:
        keys = client.list_access_keys()
        print(keys)
    except Exception as e:
        print(f"list_access_keys: {repr(e)}")


def list_keys(client, username):
    session = boto3.Session(profile_name='mfa')
    client: IAMClient = session.client('iam')
    return client.list_access_keys(UserName=username)['AccessKeyMetadata']


def main():
    # session = boto3.Session(profile_name='mfa')
    # client: IAMClient = session.client('iam')
    # client.create_access_key(UserName='andyg')
    device = get_user_mfa_device()
    print(device)


if __name__ == '__main__':
    main()
