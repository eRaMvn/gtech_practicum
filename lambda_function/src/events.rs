pub static ATTACH_ROLE_POLICY_EVENT: &str = r#"
{
	"version": "0",
	"id": "a94961ac-7f2a-83b9-3abf-de1f93e670fa",
	"detail-type": "AWS API Call via CloudTrail",
	"source": "aws.iam",
	"account": "01234567890",
	"time": "2023-05-30T05:07:19Z",
	"region": "us-east-1",
	"resources": [],
	"detail": {
		"eventVersion": "1.08",
		"userIdentity": {
			"type": "IAMUser",
			"principalId": "AIDAJ24KHYAI5C3A47F6W",
			"arn": "arn:aws:iam::01234567890:user/john.doe",
			"accountId": "01234567890",
			"accessKeyId": "ASIAQG44ZLVNEJGB3X52",
			"userName": "john.doe",
			"sessionContext": {
				"sessionIssuer": {},
				"webIdFederationData": {},
				"attributes": {
					"creationDate": "2023-05-30T04:43:55Z",
					"mfaAuthenticated": "true"
				}
			}
		},
		"eventTime": "2023-05-30T05:07:19Z",
		"eventSource": "iam.amazonaws.com",
		"eventName": "AttachRolePolicy",
		"awsRegion": "us-east-1",
		"sourceIPAddress": "68.21.163.122",
		"userAgent": "AWS Internal",
		"requestParameters": {
			"roleName": "practicum_test_role1",
			"policyArn": "arn:aws:iam::01234567890:policy/AllowKMS"
		},
		"responseElements": "None",
		"requestID": "1384e241-0de2-4a22-a590-f8fa8c7ecf61",
		"eventID": "b4a1e100-9d46-4580-a140-dd65f7a0f415",
		"readOnly": "False",
		"eventType": "AwsApiCall",
		"managementEvent": "True",
		"recipientAccountId": "01234567890",
		"eventCategory": "Management",
		"sessionCredentialFromConsole": "true"
	}
}
"#;

pub static DETACH_ROLE_POLICY_EVENT: &str = r#"
{
    "version": "0",
    "id": "9a98d033-189f-b69e-fab5-96c6599c7bd4",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "014824332634",
    "time": "2023-05-31T04:44:57Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJ24KHYAI5C3A47F6W",
            "arn": "arn:aws:iam::014824332634:user/thien",
            "accountId": "014824332634",
            "accessKeyId": "ASIAQG44ZLVNLHDE7DRA",
            "userName": "thien",
            "sessionContext": {
                "sessionIssuer": {},
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-05-31T04:35:39Z",
                    "mfaAuthenticated": "true"
                }
            }
        },
        "eventTime": "2023-05-31T04:44:57Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "DetachRolePolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "68.21.163.122",
        "userAgent": "AWS Internal",
        "requestParameters": {
            "roleName": "practicum_test_role1",
            "policyArn": "arn:aws:iam::014824332634:policy/movie-db-policy"
        },
        "responseElements": null,
        "requestID": "1e62a688-f9ba-438b-8075-40d9ee223fcd",
        "eventID": "ae57b68d-c752-4cb2-a2cf-ccaa83d99979",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "managementEvent": true,
        "recipientAccountId": "014824332634",
        "eventCategory": "Management",
        "sessionCredentialFromConsole": "true"
    }
}
"#;

pub static CREATE_POLICY_VERSION_EVENT: &str = r#"
{
    "version": "0",
    "id": "9c31d5a6-8fd4-7747-6238-e825827708ca",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "014824332634",
    "time": "2023-05-31T04:56:44Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJ24KHYAI5C3A47F6W",
            "arn": "arn:aws:iam::014824332634:user/thien",
            "accountId": "014824332634",
            "accessKeyId": "ASIAQG44ZLVNLHDE7DRA",
            "userName": "thien",
            "sessionContext": {
                "sessionIssuer": {},
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-05-31T04:35:39Z",
                    "mfaAuthenticated": "true"
                }
            }
        },
        "eventTime": "2023-05-31T04:56:44Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreatePolicyVersion",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "68.21.163.122",
        "userAgent": "AWS Internal",
        "requestParameters": {
            "setAsDefault": true,
            "policyArn": "arn:aws:iam::014824332634:policy/Dome9CloudBots",
            "policyDocument": "{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"CloudSupervisor\",\n            \"Effect\": \"Allow\",\n            \"Action\": [\n                \"cloudtrail:StartLogging\",\n                \"cloudtrail:UpdateTrail\",\n                \"cloudwatch:PutMetricAlarm\",\n                \"config:PutConfigurationRecorder\",\n                \"config:PutDeliveryChannel\",\n                \"config:StartConfigurationRecorder\",\n                \"ec2:AssociateIamInstanceProfile\",\n                \"ec2:AuthorizeSecurityGroupEgress\",\n                \"ec2:AuthorizeSecurityGroupIngress\",\n                \"ec2:CreateFlowLogs\",\n                \"ec2:CreateSecurityGroup\",\n                \"ec2:CreateTags\",\n                \"ec2:CreateSnapshot\",\n                \"ec2:DeleteSecurityGroup\",\n                \"ec2:DetachInternetGateway\",\n                \"ec2:DeleteInternetGateway\",\n                \"ec2:DescribeAddresses\",\n                \"ec2:DescribeSecurityGroups\",\n                \"ec2:DescribeInstances\",\n                \"ec2:DisassociateAddress\",\n                \"ec2:ModifyInstanceAttribute\",\n                \"ec2:ModifyImageAttribute\",\n                \"ec2:MonitorInstances\",\n                \"ec2:ReleaseAddress\",\n                \"ec2:RevokeSecurityGroupEgress\",\n                \"ec2:RevokeSecurityGroupIngress\",\n                \"ec2:StopInstances\",\n                \"ec2:TerminateInstances\",\n                \"kms:EnableKeyRotation\",\n                \"iam:AttachRolePolicy\",\n                \"iam:AttachUserPolicy\",\n                \"iam:CreatePolicy\",\n                \"iam:CreateRole\",\n                \"iam:GetPolicy\",\n                \"iam:PassRole\",\n                \"iam:UpdateAccountPasswordPolicy\",\n                \"iam:UpdateLoginProfile\",\n                \"logs:PutMetricFilter\",\n                \"logs:CreateLogGroup\",\n                \"rds:ModifyDBInstance\",\n                \"s3:CreateBucket\",\n                \"s3:DeleteBucket\",\n                \"s3:DeleteBucketPolicy\",\n                \"s3:GetBucketAcl\",\n                \"s3:GetBucketPolicy\",\n                \"s3:GetObject\",\n                \"s3:HeadBucket\",\n                \"s3:PutBucketAcl\",\n                \"s3:PutBucketLogging\",\n                \"s3:PutBucketPolicy\",\n                \"s3:PutBucketVersioning\",\n                \"s3:PutEncryptionConfiguration\",\n                \"s3:PutObject\",\n                \"sns:Publish\",\n                \"sns:CreateTopic\",\n                \"sns:Subscribe\",\n                \"sts:GetCallerIdentity\",\n                \"sts:AssumeRole\"\n            ],\n            \"Resource\": \"*\"\n        }\n    ]\n}"
        },
        "responseElements": {
            "policyVersion": {
                "isDefaultVersion": true,
                "createDate": "May 31, 2023 4:56:44 AM",
                "versionId": "v2"
            }
        },
        "requestID": "a6bbbd04-1b14-4c6b-8a7c-b61876c1da1b",
        "eventID": "537fc095-f50f-4a48-a463-24d54c706a6f",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "managementEvent": true,
        "recipientAccountId": "014824332634",
        "eventCategory": "Management",
        "sessionCredentialFromConsole": "true"
    }
}
"#;

pub static DELETE_POLICY_EVENT: &str = r#"
{
    "version": "0",
    "id": "f177268d-e921-d9cb-ced8-0d5e5f1efcce",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "014824332634",
    "time": "2023-05-31T05:05:51Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJ24KHYAI5C3A47F6W",
            "arn": "arn:aws:iam::014824332634:user/thien",
            "accountId": "014824332634",
            "accessKeyId": "ASIAQG44ZLVNLHDE7DRA",
            "userName": "thien",
            "sessionContext": {
                "sessionIssuer": {},
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-05-31T04:35:39Z",
                    "mfaAuthenticated": "true"
                }
            }
        },
        "eventTime": "2023-05-31T05:05:51Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "DeletePolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "68.21.163.122",
        "userAgent": "AWS Internal",
        "requestParameters": {
            "policyArn": "arn:aws:iam::014824332634:policy/test-policy"
        },
        "responseElements": null,
        "requestID": "0b8dfbca-b2ed-4f35-a603-c1592d0fec71",
        "eventID": "862da43f-b678-4f11-82de-0685afcdfe16",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "managementEvent": true,
        "recipientAccountId": "014824332634",
        "eventCategory": "Management",
        "sessionCredentialFromConsole": "true"
    }
}
"#;

pub static DELETE_ROLE_EVENT: &str = r#"
{
    "version": "0",
    "id": "526b0c94-6818-c31d-4a54-2c1a27d69703",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "014824332634",
    "time": "2023-05-31T05:10:09Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJ24KHYAI5C3A47F6W",
            "arn": "arn:aws:iam::014824332634:user/thien",
            "accountId": "014824332634",
            "accessKeyId": "ASIAQG44ZLVNLHDE7DRA",
            "userName": "thien",
            "sessionContext": {
                "sessionIssuer": {},
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-05-31T04:35:39Z",
                    "mfaAuthenticated": "true"
                }
            }
        },
        "eventTime": "2023-05-31T05:10:09Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "DeleteRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "68.21.163.122",
        "userAgent": "AWS Internal",
        "requestParameters": {
            "roleName": "practicum_test_role1"
        },
        "responseElements": null,
        "requestID": "237661d5-4108-4e64-bef8-67192eee6e92",
        "eventID": "04856c00-ba33-4dc0-8030-9332c09464e3",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "managementEvent": true,
        "recipientAccountId": "014824332634",
        "eventCategory": "Management",
        "sessionCredentialFromConsole": "true"
    }
}
"#;

pub static PUT_ROLE_POLICY_EVENT: &str = r#"
{
    "version": "0",
    "id": "f5a1bcbd-e3c6-9d0e-4d60-f0be237c35be",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "014824332634",
    "time": "2023-05-31T05:32:08Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJ24KHYAI5C3A47F6W",
            "arn": "arn:aws:iam::014824332634:user/thien",
            "accountId": "014824332634",
            "accessKeyId": "ASIAQG44ZLVNJO2HJMNI",
            "userName": "thien",
            "sessionContext": {
                "sessionIssuer": {},
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-05-31T04:35:39Z",
                    "mfaAuthenticated": "true"
                }
            }
        },
        "eventTime": "2023-05-31T05:32:08Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "PutRolePolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "68.21.163.122",
        "userAgent": "AWS Internal",
        "requestParameters": {
            "roleName": "practicum_test_role_inline",
            "policyDocument": "{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"VisualEditor0\",\n            \"Effect\": \"Allow\",\n            \"Action\": [\n                \"s3:ListStorageLensConfigurations\",\n                \"s3:ListAccessPointsForObjectLambda\",\n                \"s3:ListBucketMultipartUploads\",\n                \"s3:ListAllMyBuckets\",\n                \"s3:ListAccessPoints\",\n                \"s3:ListJobs\",\n                \"s3:ListBucketVersions\",\n                \"s3:ListBucket\",\n                \"s3:ListMultiRegionAccessPoints\",\n                \"s3:ListMultipartUploadParts\"\n            ],\n            \"Resource\": \"*\"\n        }\n    ]\n}",
            "policyName": "test_inline_policy1"
        },
        "responseElements": null,
        "requestID": "041a4bc6-56e4-48db-8ec2-e4cfd5e66e1d",
        "eventID": "b3e9d0d3-e685-4a54-b3a4-31c0b6e3b030",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "managementEvent": true,
        "recipientAccountId": "014824332634",
        "eventCategory": "Management",
        "sessionCredentialFromConsole": "true"
    }
}
"#;

pub static DELETE_ROLE_POLICY_EVENT: &str = r#"
{
    "version": "0",
    "id": "9ea8662e-dfbc-b548-8327-7027e86bfceb",
    "detail-type": "AWS API Call via CloudTrail",
    "source": "aws.iam",
    "account": "014824332634",
    "time": "2023-05-31T05:37:26Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAJ24KHYAI5C3A47F6W",
            "arn": "arn:aws:iam::014824332634:user/thien",
            "accountId": "014824332634",
            "accessKeyId": "ASIAQG44ZLVNLHDE7DRA",
            "userName": "thien",
            "sessionContext": {
                "sessionIssuer": {},
                "webIdFederationData": {},
                "attributes": {
                    "creationDate": "2023-05-31T04:35:39Z",
                    "mfaAuthenticated": "true"
                }
            }
        },
        "eventTime": "2023-05-31T05:37:26Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "DeleteRolePolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "68.21.163.122",
        "userAgent": "AWS Internal",
        "requestParameters": {
            "roleName": "practicum_test_role_inline",
            "policyName": "test_inline_policy2"
        },
        "responseElements": null,
        "requestID": "7ef9b0d7-c7eb-4e92-bb9d-8891214e221a",
        "eventID": "f8a297b2-8f68-43ad-b703-9460d70c0963",
        "readOnly": false,
        "eventType": "AwsApiCall",
        "managementEvent": true,
        "recipientAccountId": "014824332634",
        "eventCategory": "Management",
        "sessionCredentialFromConsole": "true"
    }
}
"#;
