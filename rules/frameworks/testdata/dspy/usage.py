"""DSPy usage fixture — positive and negative cases."""
import dspy  # airom: dspy/import

# airom: dspy/module
qa = dspy.Predict("question -> answer")
cot = dspy.ChainOfThought("q -> a")  # airom: dspy/module

# airom-ok: dspy/import
note = "dspy is a framework"

# airom-ok: dspy/module
doc = "dspy.Predict explained"
