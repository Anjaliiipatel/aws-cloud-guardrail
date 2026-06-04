import boto3

# Initialize the S3 client
s3 = boto3.client('s3')

def audit_s3_buckets():
    print("--- Starting S3 Security Audit ---\n")
    
    # List all buckets in your account
    response = s3.list_buckets()
    
    for bucket in response['Buckets']:
        name = bucket['Name']
        print(f"Checking Bucket: {name}")

        # 1. Check for Public Access
        try:
            public_status = s3.get_public_access_block(Bucket=name)
            # If all these are True, the bucket is shielded from the public
            config = public_status['PublicAccessBlockConfiguration']
            if all(config.values()):
                print("  [✅] Public Access: Blocked (Secure)")
            else:
                print("  [❌] Public Access: NOT fully blocked (Risky!)")
        except:
            print("  [⚠️] Public Access: No configuration found (Danger!)")

        # 2. Check for Encryption at Rest
        try:
            encryption = s3.get_bucket_encryption(Bucket=name)
            print("  [✅] Encryption: Enabled")
        except:
            print("  [❌] Encryption: DISABLED (Vulnerable)")

        print("-" * 30)

if __name__ == "__main__":
    audit_s3_buckets()

