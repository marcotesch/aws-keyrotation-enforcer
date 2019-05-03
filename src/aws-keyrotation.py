'''AWS KeyRotation Enforcer Module, can be used to enforce that AWS Access Keys are rotated regularly'''

import boto3


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


if __name__ == "__main__":
    iamClient = boto3.client('iam')
    iamUsers = __getAwsIamUserList(iamClient)
    iamAccessKeys = __getAwsAccessKeyAge(iamClient, iamUsers)
