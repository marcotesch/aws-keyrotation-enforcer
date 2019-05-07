# aws-keyrotation-enforcer
AWS Lambda Skripts to automatically enforce the rotation of AWS Access Keys with a certain age.

Used Environment Variables:
- SOURCEMAIL (required): Used as source E-Mail adresse in AWS SES
- NOTIFYKEYAGE: Key age in days after which a notification will be send to the technical contact

> The Key age for deactivation is calculated based on the NOTIFYKEYAGE. It is greater by 7 days, meaning the user has 7 days to rotate the AWS Access Key after he recieved the first notice. If the key is not rotated within that timeframe the key will be deactivated.

A sample diagramm on how the script is intended to be used can be seen below:

![Architecture Diagramm](assets/aws-keyrotation-enforcer.svg)

## Needed AWS IAM Permissions for Execution

The following minimal permissions are needed in Order for the Lambda Function to work properly.

```javascript
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ListAccessKeys",
        "iam:UpdateAccessKey"
      ],
      "Resource": "arn:aws:iam::*:user/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListUserTags"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "logs:CreateLogGroup",
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": "ses:SendEmail",
      "Resource": "arn:aws:ses:*:*:identity/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/*:*"
      ]
    }
  ]
}
```