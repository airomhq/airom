"""Azure ML serving fixture — positive and negative cases."""
from azure.ai.ml import MLClient  # airom: azureml/import
import azureml.core  # airom: azureml/import

# airom: azureml/mlclient
ml_client = MLClient(credential, sub_id, rg, ws)

# airom-ok: azureml/import
note = "azureml workspace overview"

# airom-ok: azureml/mlclient
doc = "MLClient manages online endpoints"
