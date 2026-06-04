import boto3
import json

s3 = boto3.client('s3')

def lambda_handler(event, context):
    print("--- Starting Automated S3 Remediation ---")
    response = s3.list_buckets()
    results = []
    
    for bucket in response['Buckets']:
        name = bucket['Name']
        
        # 1. Fix Public Access
        s3.put_public_access_block(
            Bucket=name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
            }
        )
        
        # 2. Fix Encryption
        s3.put_bucket_encryption(
            Bucket=name,
            ServerSideEncryptionConfiguration={
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        )
        
        results.append(f"Remediated: {name}")
    
    return {
        'statusCode': 200,
        'body': json.dumps(results)
    }
import boto3
import json

# Configuration
SNS_TOPIC_ARN = "arn:aws:sns:us-east-2:520089507142:SecurityAlerts"
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
ec2_client = boto3.client('ec2') # Used to get all regions

def get_all_regions():
    return [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

def remediate_all_regions():
    regions = get_all_regions()
    remediated_list = []

    for region in regions:
        # Connect to S3 in each specific region
        regional_s3 = boto3.client('s3', region_name=region)
        try:
            buckets = regional_s3.list_buckets()['Buckets']
            for b in buckets:
                name = b['Name']
                # FIX: Encryption (MITRE T1530)
                regional_s3.put_bucket_encryption(
                    Bucket=name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
                    }
                )
                remediated_list.append(f"Region: {region} | Bucket: {name} (Applied AES-256)")
        except Exception as e:
            continue # Some regions might be restricted

    # SEND SNS ALERT
    if remediated_list:
        message = "🚨 CloudSentinel Alert: Automated Remediation Performed\n\n" + "\n".join(remediated_list)
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="CloudSentinel Security Guardrail Action",
            Message=message
        )
    return remediated_list

