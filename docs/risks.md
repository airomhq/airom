# Artifact risks

AIROM surfaces an **artifact-risk overlay**: structural, statically-detected
properties of a model artifact that enable code execution or content injection
at load time — a poisoned checkpoint, an unsafe deserialization surface. Risks
are attributes of components already in the AIBOM, not a separate security
scan: every risk points at a component and carries `file`/offset evidence.

> **A risk is suspicion with evidence, never a verdict.** The absence of risks
> is not a safety claim (static analysis is evadable by construction), and a
> flagged risk is not a malware conviction. Treat it as "load this in a
> sandbox and look," not "this is malware."

## How risks appear in output

| Format | Where |
|--------|-------|
| CycloneDX | top-level `vulnerabilities[]` — a non-CVE `id` with `source.name: airom`, `ratings[].method: other` (no CVSS is claimed), and `affects[].ref` pointing at the component's `bom-ref`. Legacy `airom:pickle.*` component properties are also emitted for one release. |
| SARIF | a `risk/<slug>` rule carrying the GitHub `security-severity` marker, and a result (level `error`/`warning`/`note` by severity) on the affected artifact — so a poisoned checkpoint shows up as a security alert on the PR that introduced it. |
| Native JSON / YAML | `component.risks[]` — `{id, severity, detail, occurrence}`. |
| `--fail-on` | `risk` (any), `risk:<severity>`, or `risk:<slug>`. |

Severity is a **fixed function of the risk id** (never judgment at scan time),
so output is deterministic.

## Coverage bounds

Artifact-risk scans read a **bounded** prefix of each file — the same
`--max-file-size` cap (default 1 MiB) every content detector uses, so peak
memory stays a function of configuration, not input size. A risk signal placed
**beyond** that bound is not inspected: a GGUF `chat_template` pushed past 1 MiB
by a large preceding vocab, or a `Lambda` declared deep in an oversized Keras
config, can evade the scan while a runtime that reads the whole file still
executes it. Raise `--max-file-size` to widen the window. As with the static
pickle walk, **absence of a risk is not a safety claim** — a clean scan of a
capped read means "nothing dangerous in the inspected prefix," not "safe."

## Catalog

<a id="pickle-import"></a>

### AIROM-RISK-PICKLE-IMPORT — Unsafe pickle import · **high**

`--fail-on` slug: `pickle-import` (alias: `pickle-risk`)

A pickle `GLOBAL` (or `STACK_GLOBAL`) opcode resolves to a code-execution
callable — `os.system`, `builtins.eval`/`exec`, anything under `subprocess`,
`runpy`, `socket`, `importlib`, and similar. Because Python's `pickle`
executes these imports while *unpickling*, loading such a checkpoint
(`torch.load`, `pickle.load`, `joblib.load`) runs attacker-controlled code
before any model is produced. `detail` carries the exact dotted callables
found (e.g. `os.system`, `subprocess.Popen`).

Detected by a static pickle-opcode walk (`modelfilex/torch`); the file's bytes
are never executed and the tensor data is never read.

<a id="keras-lambda"></a>

### AIROM-RISK-KERAS-LAMBDA — Keras Lambda layer · **high**

`--fail-on` slug: `keras-lambda`

A Keras model config declares a `Lambda` layer. A Lambda layer stores arbitrary
Python as a marshalled code object inside the config, and `keras.models.load_model`
(or `Model.from_config`) executes it while reconstructing the model — a code-execution
vector that fires on load, before inference. `detail` records `Lambda`.

Detected by scanning the model config a Keras `.h5`/`.hdf5` stores as a verbatim
string (`modelfilex/hdf5`) for the `"class_name": "Lambda"` signature. This is a
bounded substring scan over the header/content the detector already reads, not a
full HDF5 parse; a `.keras` (zip) container is not yet covered.

<a id="gguf-template"></a>

### AIROM-RISK-GGUF-TEMPLATE — Unsafe GGUF chat template · **medium**

`--fail-on` slug: `gguf-template`

The GGUF `tokenizer.chat_template` metadata is a Jinja template rendered at
prompt-format time. A legitimate template only iterates messages and formats
strings; this risk fires when it contains sandbox-escape gadgets — a dunder
attribute traversal (`__globals__`, `__subclasses__`, `__class__`,
`__builtins__`, `__import__`, …) or a direct `os.popen`/`os.system`/`subprocess`
call — that a server-side-template-injection payload uses to reach the Python
runtime. Jinja pivot objects that real templates legitimately use (notably
`namespace(...)` for loop state) are deliberately not flagged; the dangerous use
of any pivot still trips a dunder token. `detail` lists the matched gadgets.

Detected during GGUF header-metadata parsing (`modelfile/gguf`) — no tensor
data is read.

<a id="savedmodel-pyfunc"></a>

### AIROM-RISK-SAVEDMODEL-PYFUNC — SavedModel Python-callback op · **medium**

`--fail-on` slug: `savedmodel-pyfunc`

A TensorFlow SavedModel graph contains a `PyFunc`-family op (`PyFunc`,
`PyFuncStateless`, `EagerPyFunc`), which invokes a registered Python callable
during graph execution. `detail` names the specific op(s).

Detected by scanning the `saved_model.pb` protobuf the detector already reads
(`modelfilex/savedmodel`) for the op-name strings. This is a presence signal:
the op is a legitimate TensorFlow primitive, but an unexpected one in a
distributed artifact warrants review.

_Planned additions (`.keras`-zip Lambda, TFLite custom ops, pickle memo-evasion
surfacing) are tracked in [ROADMAP.md](./ROADMAP.md)._
