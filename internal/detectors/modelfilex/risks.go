package modelfilex

import (
	"bytes"
	"sort"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// This file carries the artifact-risk scans layered onto the modelfilex
// detectors. Each scan works over bytes the detector has ALREADY read (a
// bounded header/content buffer, never the tensor payload), so it adds no
// memory beyond the existing read (P2). The scans are presence signals with
// evidence, never verdicts (docs/risks.md).

// kerasLambdaSigs are the Keras model_config JSON signatures for a Lambda
// layer, covering json.dumps' default (`": "`) and compact (`":"`) separators.
// A Keras .h5/.keras stores its model_config as a plain string, so the JSON
// appears verbatim in the file bytes — a substring scan is a faithful, bounded
// presence check without a full HDF5/zip parse.
var kerasLambdaSigs = [][]byte{
	[]byte(`"class_name": "Lambda"`),
	[]byte(`"class_name":"Lambda"`),
}

// hasKerasLambda reports whether the model config declares a Lambda layer.
func hasKerasLambda(content []byte) bool {
	for _, sig := range kerasLambdaSigs {
		if bytes.Contains(content, sig) {
			return true
		}
	}
	return false
}

// kerasLambdaRisk returns the risk claim for a Lambda-bearing config, or nil.
func kerasLambdaRisk(content []byte) []detect.RiskClaim {
	if !hasKerasLambda(content) {
		return nil
	}
	return []detect.RiskClaim{{ID: airom.RiskKerasLambda, Detail: []string{"Lambda"}}}
}

// pyFuncOps are the TensorFlow graph ops that execute a Python callable. Their
// exact names appear as length-delimited protobuf string fields in a
// SavedModel's graph_def (op names, function names, attr values).
var pyFuncOps = []string{"PyFunc", "PyFuncStateless", "EagerPyFunc"}

// savedModelPyFuncRisk returns the risk claim for a graph containing a
// PyFunc-family op, or nil. Each op is matched on its protobuf length-prefix
// byte (a length-delimited string field is <len><bytes>, and every op name is
// < 128 bytes so the length is one byte). That anchor rejects a benign
// identifier that merely embeds the letters ("MyPyFunctionalLayer") and lets
// each distinct op match independently — <0x06>PyFunc is not a substring of
// <0x0b>EagerPyFunc — so no fragile substring dedup is needed.
func savedModelPyFuncRisk(content []byte) []detect.RiskClaim {
	var detail []string
	for _, op := range pyFuncOps {
		// op names are short compile-time constants (< 128 bytes), so the
		// length is a single protobuf varint byte.
		framed := append([]byte{byte(len(op))}, op...) // #nosec G115 -- len(op) < 128 for every pyFuncOps entry
		if bytes.Contains(content, framed) {
			detail = append(detail, op)
		}
	}
	if len(detail) == 0 {
		return nil
	}
	sort.Strings(detail)
	return []detect.RiskClaim{{ID: airom.RiskSavedModelPyFunc, Detail: detail}}
}
