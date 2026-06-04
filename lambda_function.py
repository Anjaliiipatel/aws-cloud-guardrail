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

