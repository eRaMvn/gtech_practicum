def upload_file_to_s3(data, bucket_name, key, s3_client):
    s3_client.put_object(Bucket=bucket_name, Key=key, Body=data)


def list_objects_in_s3(bucket_name, path, s3_client):
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=path)

    # Iterate over the objects and print their keys
    if "Contents" in response:
        return [obj["Key"] for obj in response["Contents"]]
    else:
        return []
