"""Ray Serve fixture — positive and negative cases."""
from ray import serve  # airom: rayserve/import

# airom: rayserve/deployment
@serve.deployment
class Model:
    def __call__(self, req):
        return "ok"

# airom-ok: rayserve/import
note = "ray import serve is the entrypoint"

# airom-ok: rayserve/deployment
doc = "decorate with serve.deployment"
