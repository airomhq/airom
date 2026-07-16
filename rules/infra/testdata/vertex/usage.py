"""Vertex AI serving fixture — positive and negative cases."""
from google.cloud import aiplatform  # airom: vertex/import
import vertexai  # airom: vertex/import

# airom: vertex/endpoint
ep = aiplatform.Endpoint("projects/p/locations/us/endpoints/123")

# airom-ok: vertex/import
note = "vertexai hosts the model"

# airom-ok: vertex/endpoint
doc = "aiplatform.Endpoint wraps a deployment"
