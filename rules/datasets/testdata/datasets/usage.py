"""Dataset-reference fixture — positive and negative cases."""
from datasets import load_dataset
import kagglehub

# airom: datasets/load-dataset
ds = load_dataset("Anthropic/hh-rlhf")
squad = load_dataset("squad", split="train")  # airom: datasets/load-dataset

# airom: datasets/kagglehub
path = kagglehub.dataset_download("zynicide/wine-reviews")

# airom: datasets/kaggle-cli
cmd = "kaggle datasets download -d zynicide/wine-reviews"

# airom-ok: datasets/load-dataset
note = "load_dataset returns a DatasetDict"

# airom-ok: datasets/kagglehub
doc = "kagglehub.dataset_download fetches files"

# airom-ok: datasets/kaggle-cli
txt = "kaggle datasets download needs auth first"
