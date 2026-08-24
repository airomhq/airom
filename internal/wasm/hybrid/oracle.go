package hybrid

import (
	"fmt"
)

// AccuracyScoreboard holds empirical precision, recall, and F1 metrics.
type AccuracyScoreboard struct {
	TruePositives          int     `json:"truePositives"`
	FalsePositives         int     `json:"falsePositives"`
	FalseNegatives         int     `json:"falseNegatives"`
	TrueNegatives          int     `json:"trueNegatives"`
	Precision              float64 `json:"precision"`
	Recall                 float64 `json:"recall"`
	F1Score                float64 `json:"f1Score"`
	FastPathSkippedFiles   int     `json:"fastPathSkippedFiles"`
	ASTEvaluatedFiles      int     `json:"astEvaluatedFiles"`
	FalsePositiveReduction float64 `json:"falsePositiveReduction"`
}

// AccuracyOracle compares ground-truth labeled corpus findings against scanner extractions.
type AccuracyOracle struct {
	tp        int
	fp        int
	fn        int
	tn        int
	skipped   int
	evaluated int
}

// NewAccuracyOracle constructs an oracle.
func NewAccuracyOracle() *AccuracyOracle {
	return &AccuracyOracle{}
}

// RecordObservation records a single classification outcome.
func (o *AccuracyOracle) RecordObservation(isActuallyAI, predictedAI bool, wasEvaluatedWithAST bool) {
	if wasEvaluatedWithAST {
		o.evaluated++
	} else {
		o.skipped++
	}

	if isActuallyAI && predictedAI {
		o.tp++
	} else if !isActuallyAI && predictedAI {
		o.fp++
	} else if isActuallyAI && !predictedAI {
		o.fn++
	} else {
		o.tn++
	}
}

// Scoreboard computes the aggregate statistical scores.
func (o *AccuracyOracle) Scoreboard() AccuracyScoreboard {
	prec := 1.0
	if o.tp+o.fp > 0 {
		prec = float64(o.tp) / float64(o.tp+o.fp)
	}

	rec := 1.0
	if o.tp+o.fn > 0 {
		rec = float64(o.tp) / float64(o.tp+o.fn)
	}

	f1 := 0.0
	if prec+rec > 0 {
		f1 = 2 * (prec * rec) / (prec + rec)
	}

	fpReduction := 0.0
	if o.tn+o.fp > 0 {
		fpReduction = float64(o.tn) / float64(o.tn+o.fp)
	}

	return AccuracyScoreboard{
		TruePositives:          o.tp,
		FalsePositives:         o.fp,
		FalseNegatives:         o.fn,
		TrueNegatives:          o.tn,
		Precision:              prec,
		Recall:                 rec,
		F1Score:                f1,
		FastPathSkippedFiles:   o.skipped,
		ASTEvaluatedFiles:      o.evaluated,
		FalsePositiveReduction: fpReduction,
	}
}

// FormatTable prints an ASCII scoreboard summary.
func (s AccuracyScoreboard) FormatTable() string {
	return fmt.Sprintf(`
┌─ Accuracy Oracle Scoreboard ───────────────────┐
│ Precision:     %6.2f%%                          │
│ Recall:        %6.2f%%                          │
│ F1-Score:      %6.2f%%                          │
│ FastPath Skip: %d files (zero AST cost)         │
│ AST Evaluated: %d files                         │
│ FP Reduction:  %6.2f%%                          │
└────────────────────────────────────────────────┘`,
		s.Precision*100, s.Recall*100, s.F1Score*100, s.FastPathSkippedFiles, s.ASTEvaluatedFiles, s.FalsePositiveReduction*100)
}
