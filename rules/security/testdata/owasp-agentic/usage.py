"""Fixture for owasp-agentic security rule pack.

Positives flag unsafe evaluation of LLM response and unconstrained shell tools.
Negatives use safe parsers (e.g. json.loads) and constrained tools.
"""

import json

# airom: owasp-agentic/insecure-eval
result = eval(response)

# airom: owasp-agentic/insecure-eval
res2 = exec(output)

# Negative — json.loads on response is safe
# airom-ok: owasp-agentic/insecure-eval
parsed = json.loads(response)

# Negative — eval on safe hardcoded literal
# airom-ok: owasp-agentic/insecure-eval
safe_eval = eval("1 + 1")

# Positive — unconstrained shell tool instantiation
# airom: owasp-agentic/unconstrained-shell-tool
shell_tool = ShellTool()

# Positive — Python REPL agent tool
# airom: owasp-agentic/unconstrained-shell-tool
repl = PythonREPL()

# Negative — safe constrained tool
# airom-ok: owasp-agentic/unconstrained-shell-tool
calculator = CalculatorTool()
