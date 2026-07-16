"""MLflow usage fixture — positive and negative cases."""
import mlflow  # airom: mlflow/import
import mlflow.langchain  # airom: mlflow/import

# airom: mlflow/flavor-logmodel
mlflow.openai.log_model(model, "model")
mlflow.langchain.autolog()  # airom: mlflow/flavor-logmodel

# airom-ok: mlflow/import
note = "mlflow tracking server"

# airom-ok: mlflow/flavor-logmodel
doc = "log_model documentation"
