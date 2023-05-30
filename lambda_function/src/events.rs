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
