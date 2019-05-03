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
                'CreateDate': accessKey['CreateDate']
            })

        if len(accessKeyInfos) > 0:
            iamAccessKeys['Keys'].append({
                'UserName': iamUser['UserName'],
                'AccessKeyInfos': accessKeyInfos
            })

    return iamAccessKeys


def __getNotifyKeyAgeDate(ageDays):
    '''get datetime before which a notification should be send out'''
    notifyKeyAgeDate = datetime.now() - timedelta(days=ageDays)
    return notifyKeyAgeDate


def __identifyKeyAges(iamAccessKeys, notifyKeyAgeDate):
    '''identify all old Access Keys'''

    for iamAccessKey in iamAccessKeys['Keys']:
        for accessKeyInfo in iamAccessKey['AccessKeyInfos']:
            if accessKeyInfo['CreateDate'].replace(tzinfo=None) < notifyKeyAgeDate:
                print('Found one!')


if __name__ == "__main__":

    logging.basicConfig(stream=sys.stdout)
    logger = logging.getLogger('aws-keyrotation')
    logger.setLevel(logging.INFO)

    try:
        notifyKeyAge = int(os.environ['NOTIFYKEYAGE'])
    except KeyError:
        logger.info(
            'No NOTIFYKEYAGE environment variable found. Fallback to default (Days=30)')
        notifyKeyAge = 30

    notifyKeyAgeDate = __getNotifyKeyAgeDate(notifyKeyAge)

    iamClient = boto3.client('iam')
    iamUsers = __getAwsIamUserList(iamClient)
    iamAccessKeys = __getAwsAccessKeyAge(iamClient, iamUsers)

    __identifyKeyAges(iamAccessKeys, notifyKeyAgeDate)
