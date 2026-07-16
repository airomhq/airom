"""SageMaker serving fixture — positive and negative cases."""
import sagemaker  # airom: sagemaker/import
import boto3

# airom: sagemaker/runtime
rt = boto3.client("sagemaker-runtime")
resp = rt.invoke_endpoint(EndpointName="my-ep", Body=payload)  # airom: sagemaker/runtime

# airom-ok: sagemaker/import
note = "sagemaker hosts the endpoint"

# airom-ok: sagemaker/runtime
doc = "call invoke endpoint on the runtime"
