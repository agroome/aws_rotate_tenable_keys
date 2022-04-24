# aws_rotate_tenable_keys
This is an AWS lambda function designed to work as a rotation function for api keys stored in AWS SecretsManager. 


## Installation

### Method one - using the AWS SAM CLI
Create and deploy as CloudFormation stack 
using the AWS Serverless Application Manager client.

#### Requirements
Generating new API keys using the Tenable.io API requires an Administrator account.
#### Prerequisites
Deploying as a cloud formation stack assumes that you have: 
* [Installed the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
* [Set up AWS credentials](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-getting-started-set-up-credentials.html)

#### Deploying to AWS
Step one: Clone the repository
```
git clone https://github.com/agroome/aws_rotate_tenable_keys
```
Step two: Login to Tenable.io to generate an api key
* Login as an administrator account
* Go to Settings / My Account 
* Click on API KEYS in the left margin
* Click on Generate Keys, then Continue
* Copy the keys for the deployment step below

Step two: Build the CloudFormation stack with the SAM CLI
```
# change into the project folder
cd aws_rotate_tenable_keys

# build the cloudformation stack
sam build
```
Step three: Use the SAM CLI to build the CloudFormation stack
```
# Use the guided deployment to provide information specific to the deployment. 
# You will be prompted for several questions. You can call the stack anything
# you like. The ApiKeysPrefix is used to restrict the lambda function to only 
# be able to access keys with this prefix. The prefix does not need a trailing 
# slash. In the example below, a key will be created named 
# 'apikeys/tenable/jdoe@example.com'. The TioAccessKey and TioSecretKey will 
# not be echoed to the screen or written to the samconfig.toml file.
# Defaults can be chosen for the remaining answers.

# run sam deploy with the --guided option

sam deploy --guided

Configuring SAM deploy
======================

        Looking for config file [samconfig.toml] :  Not found

        Setting default arguments for 'sam deploy'
        =========================================
        Stack Name [sam-app]: rotate-tenable-keys
        AWS Region [us-east-1]: 
        Parameter ApiKeysPrefix [apikeys]: apikeys/tenable
        Parameter TioUsername [notconfigured]: jdoe@example.com
        Parameter TioAccessKey: 
        Parameter TioSecretKey:
        Parameter RotationDays [7]:
        #Shows you resources changes to be deployed and require a 'Y' to initiate deploy
        Confirm changes before deploy [y/N]:
        #SAM needs permission to be able to create roles to connect to the resources in your template
        Allow SAM CLI IAM role creation [Y/n]:
        #Preserves the state of previously provisioned resources when an operation fails
        Disable rollback [y/N]:
        Save arguments to configuration file [Y/n]: 
        SAM configuration file [samconfig.toml]: 
        SAM configuration environment [default]: 

        Looking for resources needed for deployment:
         Managed S3 bucket: aws-sam-cli-managed-default-samclisourcebucket-1d3soujy6opqr
         A different default S3 bucket can be set in samconfig.toml

        Saved arguments to config file
        Running 'sam deploy' for future deployments will use the parameters saved above.
        The above parameters can be changed by modifying samconfig.toml
        Learn more about samconfig.toml syntax at
        https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-config.html

File with same data already exists at rotate-tenable-keys/b934fdeaecffc73054d2d4a0cfe7d11d, skipping upload

        Deploying with following values
        ===============================
        Stack name                   : rotate-tenable-keys
        Region                       : us-east-1
        Confirm changeset            : False
        Disable rollback             : False
        Deployment s3 bucket         : aws-sam-cli-managed-default-samclisourcebucket-1d3soujy6opqr
        Capabilities                 : ["CAPABILITY_IAM"]
        Parameter overrides          : {"ApiKeysPrefix": "apikeys/tenable", "TioUsername": "jdoe@example.com", "TioAccessKey": "*****", "TioSecretKey": "*****", "RotationDays": 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------    
UPDATE_IN_PROGRESS                           AWS::SecretsManager::Secret                  TenableApiKey                                -
UPDATE_COMPLETE                              AWS::SecretsManager::Secret                  TenableApiKey                                -
UPDATE_COMPLETE_CLEANUP_IN_PROGRESS          AWS::CloudFormation::Stack                   rotate-tenable-keys                          -
UPDATE_COMPLETE                              AWS::CloudFormation::Stack                   rotate-tenable-keys                          -
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------    

Successfully created/updated stack - rotate-tenable-keys in us-east-1
```
If the deployment completed successfully, you should see something like the above. Note that an S3 bucked was 
created for deployment which can be removed later.

