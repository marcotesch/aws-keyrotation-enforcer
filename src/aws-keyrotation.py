'''AWS KeyRotation Enforcer Module, can be used to enforce that AWS Access Keys are rotated regularly'''

import os
import sys
import boto3
import logging
from datetime import datetime, timedelta, tzinfo


def __getAwsIamUserList(iamClient):
    '''read all AWS IAM Users, of the account'''
    response = iamClient.list_users()

    users = response['Users']

    while response['IsTruncated']:
        marker = response['Marker']
        response = iamClient.list_users(Marker=marker)

        users.append(response['Users'])

    return users


def __getAwsAccessKeyAge(iamClient, iamUsers):
    '''read the AWS IAM Access Key Age, for each provided user'''
    iamAccessKeys = {'Keys': []}

    for iamUser in iamUsers:
        response = iamClient.list_access_keys(UserName=iamUser['UserName'])

        accessKeyInfos = []

        for accessKey in response['AccessKeyMetadata']:
            accessKeyInfos.append({
                'AccessKeyId': accessKey['AccessKeyId'],
                'AccessKeyStatus': accessKey['Status'],
                'CreateDate': accessKey['CreateDate'],
                'ContactDetails': __getUserEmail(iamClient, iamUser['UserName'])
            })

        if len(accessKeyInfos) > 0:
            iamAccessKeys['Keys'].append({
                'UserName': iamUser['UserName'],
                'AccessKeyInfos': accessKeyInfos
            })

    return iamAccessKeys


def __getUserEmail(iamClient, userName):
    response = iamClient.get_user(UserName=userName)
    try:
        foundContact = False
        contactEmail = ''

        for tag in response['User']['Tags']:
            if tag['Key'] == 'Contact E-Mail':
                foundContact = True
                contactEmail = tag['Value']
                break

        if not foundContact:
            raise KeyError

    except KeyError:
        logger = logging.getLogger('aws-keyrotation')
        logger.warning('Contact details for user not provided!')

    return contactEmail


def __getNotifyKeyAgeDate(ageDays):
    '''get datetime before which a notification should be send out'''
    notifyKeyAgeDate = datetime.now() - timedelta(days=ageDays)
    return notifyKeyAgeDate


def __identifyKeyAges(iamAccessKeys, notifyKeyAgeDate):
    '''identify all old Access Keys'''
    sesClient = boto3.client('ses', region_name='eu-west-1')
    logger = logging.getLogger('aws-keyrotation')

    for iamAccessKey in iamAccessKeys['Keys']:
        for accessKeyInfo in iamAccessKey['AccessKeyInfos']:
            if accessKeyInfo['CreateDate'].replace(tzinfo=None) < notifyKeyAgeDate:
                logger.info('Old AWS Credentials found!')

                if not accessKeyInfo['ContactDetails'] == '':
                    logger.info('Notification will be send to: ' +
                                accessKeyInfo['ContactDetails'])

                    __notifyKeyAges(sesClient, accessKeyInfo)
                else:
                    logger.warning(
                        'Contact details for credentials not provided!'
                    )


def __notifyKeyAges(sesClient, keyInfo):
    logger = logging.getLogger('aws-keyrotation')

    try:
        sourceMail = os.environ['SOURCEMAIL']
    except KeyError:
        logger.warning('SOURCEMAIL environment variable not found')
        return

    try:
        response = sesClient.send_email(
            Source=sourceMail,
            Destination={
                'ToAddresses': [
                    keyInfo['ContactDetails'],
                ]
            },
            Message={
                'Subject': {
                    'Data': 'Rotate your AWS Credentials (KeyID: ' + keyInfo['AccessKeyId'] + ')'
                },
                'Body': {
                    'Text': {
                        'Data': 'Dear ' + keyInfo['ContactDetails'] + ',\n\nPlease rotate your AWS Access Key immediately.\n It will be disabled otherwise shortly if not rotated.\n\n Your AWS Keyrotation Service'
                    }
                }
            }
        )

        print(response)
    except:
        logger.warning('Notification could not be send!')


if __name__ == "__main__":

    logging.basicConfig(stream=sys.stdout)
    logger = logging.getLogger('aws-keyrotation')
    logger.setLevel(logging.INFO)

    try:
        notifyKeyAge = int(os.environ['NOTIFYKEYAGE'])
    except KeyError:
        logger.info(
            'NOTIFYKEYAGE environment variable not found.'
        )
        logger.info(
            'Fallback to default (Days=30)'
        )
        notifyKeyAge = 10

    notifyKeyAgeDate = __getNotifyKeyAgeDate(notifyKeyAge)

    iamClient = boto3.client('iam')
    iamUsers = __getAwsIamUserList(iamClient)
    iamAccessKeys = __getAwsAccessKeyAge(iamClient, iamUsers)

    __identifyKeyAges(iamAccessKeys, notifyKeyAgeDate)
