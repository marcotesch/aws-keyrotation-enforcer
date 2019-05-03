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


if __name__ == "__main__":
    iamClient = boto3.client('iam')
    __getAwsIamUserList(iamClient)
