import boto3
import json
from pprint import pprint
import logging
import urllib3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Secrets Manager Tenable API Handler
       This handler uses ...
       The Secret SecretString is expected to be a JSON string with the following format:
       {
           'username': <required: username>,
           'accessKey': <required: password>,
           'secretKey': <required: password>,
           'adminSecretArn': ..,
       }
       Args:
           event (dict): Lambda dictionary of event parameters. These keys must include the following:
               - SecretId: The secret ARN or identifier
               - ClientRequestToken: The ClientRequestToken of the secret version
               - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
           context (LambdaContext): The Lambda runtime information
    """
    logger.debug(f'event: {event}')
    # Exit early if not a valid 'Step'
    if event.get('Step') not in ['createSecret', 'finishSecret']:
        logger.debug(f'step \'{event.get("Step")}\'": not implemented for this type rotation')
        # the secrets manager calls the rotation function in four steps to test and deploy the
        # new credentials. 'generate_key' activates the new credentials, so we only need one step
        return

    # Don't proceed without the 'SecretId'
    secret_arn = event.get('SecretId')
    request_token = event.get('ClientRequestToken')
    if not (secret_arn and request_token):
        # SecretsManager service should always pass the secret arn and a request token
        logger.error(f'passed in event must have a SecretId and ClientRequestToken: {event}')
        return

    # secrets_manager = SecretsManager()
    secrets_manager = boto3.client('secretsmanager')
    secret = Secret.from_arn(secrets_manager, secret_arn)

    if event['Step'] == 'createSecret':
        # generating API keys requires admin credentials from the same domain (instance)
        # admin_secret = secrets_manager.get_admin_secret(secret.domain)
        # if not admin_secret:
        #     logger.error(f'admin secret not found for instance associated with {secret.username}')
        #     return
        # logger.info(f'discovered admin secret {admin_secret} for {secret.domain}')

        # TODO: kluge here (using the same key so only works for admins now
        current_secret = Secret.from_arn(secrets_manager, secret_arn)

        new_keys = TenableHelper(current_secret).generate_api_keys(secret.username)
        if new_keys is not None:
            secret.update_secret(new_keys)

        if False and event['Step'] == 'finishSecret':
            # First describe the secret to get the current version
            metadata = secrets_manager.describe_secret(SecretId=event['SecretId'])
            current_version = None
            for version in metadata["VersionIdsToStages"]:
                if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
                    if version == request_token:
                        # The correct version is already marked as current, return
                        logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, secret_arn))
                        return
                    current_version = version
                    break

            # Finalize by staging the secret version current
            logger.debug("finishSecret: Setting AWSCURRENT stage ")
            secrets_manager.update_secret_version_stage(
                SecretId=event['SecretId'],
                VersionStage="AWSCURRENT",
                MoveToVersionId=request_token,
                RemoveFromVersionId=current_version)
            logger.debug("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (request_token, secret_arn))


class Secret:
    @classmethod
    def from_arn(cls, secrets_manager, secret_arn: str):
        """Resolve secret details for the given arn to create a Secret"""
        logger.debug(f'Secret.from_arn: {secret_arn}')
        logger.debug(f'Secret.from_arn: {type(secrets_manager)}')
        secret = secrets_manager.describe_secret(SecretId=secret_arn)
        return cls(secrets_manager, secret)

    def __init__(self, secrets_manager, secret: dict):
        logger.debug(f'Secret.__init__: {type(secrets_manager)}')
        self.secrets_manager = secrets_manager
        value_string = self.secrets_manager.get_secret_value(SecretId=secret['ARN'])['SecretString']
        self.secret_value = json.loads(value_string)
        self.arn = secret['ARN']
        self.secret = secret
        self.tags = {tag['Key']: tag['Value'] for tag in self.secret.get('Tags', [])}
        logger.debug(f'Secret.__init__: arn: {secret["ARN"]}')
        logger.debug(f'Secret.__init__: name: {secret["Name"]}')

    @property
    def domain(self):
        return self.tags.get('tioDomain')

    @property
    def is_admin(self):
        return self.tags.get('tioRole') == 'Admin'

    @property
    def key_pair(self):
        values = self.secret_value
        return dict(accessKey=values['accessKey'], secretKey=values['secretKey'])

    @property
    def username(self):
        return self.secret_value.get('tioUsername')

    @property
    def x_api_keys(self):
        return {'X-ApiKeys': 'accessKey={accessKey};secretKey={secretKey}'.format(**self.key_pair)}

    def update_secret(self, key_pair):
        new_secret = self.secret_value
        new_secret.update(key_pair)
        self.secrets_manager.put_secret_value(
            SecretId=self.arn,
            SecretString=json.dumps(new_secret),
            VersionStages=['AWSCURRENT']
        )

    def __repr__(self):
        return f'{self.__class__.__name__}[{self.arn}]'


class TenableHelper:
    def __init__(self, admin_secret, base_url='https://cloud.tenable.com'):
        self.admin_secret = admin_secret
        self.client = urllib3.PoolManager()
        self.request_headers = {'Accept': 'application/json'}
        self.request_headers.update(self.admin_secret.x_api_keys)
        self.base_url = base_url

    def users(self):
        response = self.client.request('GET', f'{self.base_url}/users', headers=self.request_headers)
        logger.info(f'GET users() status: {response.status}')
        data = json.loads(response.data)
        logger.info(f'GET users data: {data}')
        return data.get('users')

    def get_user_id(self, username):
        for user in self.users():
            if user['username'] == username:
                break
        else:
            user = {}
        return user.get('id')

    def get_user_details(self, user_id):
        url = f'{self.base_url}/users/{user_id}'
        response = self.client.request('GET', url, headers=self.request_headers)
        return json.loads(response.data)

    def generate_api_keys(self, username: str):
        user_id = self.get_user_id(username)
        """Use the existing key pair to generate and return a new key pair"""
        url = f"https://cloud.tenable.com/users/{user_id}/keys"
        resp = self.client.request("PUT", url, headers=self.request_headers)
        if resp.status == 200:
            logger.info(f'generated new api keys for {username}')
            return json.loads(resp.data)
        else:
            logger.error(f'generate_api_keys({username})=[{resp.status}]')

