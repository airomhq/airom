#!/usr/bin/env bash
set -eo pipefail

echo "================================================================"
echo "  AIROM — Automated AI Governance & Runtime Security Scanner    "
echo "================================================================"

SCAN_PATH="${INPUT_PATH:-.}"
OUTPUT_FORMAT="${INPUT_FORMAT:-sarif}"
OUTPUT_FILE="${INPUT_OUTPUT_FILE:-airom-report.sarif}"
FAIL_ON_RISK="${INPUT_FAIL_ON_RISK:-high}"
POLICY="${INPUT_POLICY:-recommended}"

echo "[AIROM Action] Scanning path: ${SCAN_PATH}"
echo "[AIROM Action] Output format: ${OUTPUT_FORMAT}"
echo "[AIROM Action] Report destination: ${OUTPUT_FILE}"

# Execute scan with airom binary
SCAN_CMD="airom scan ${SCAN_PATH} -o ${OUTPUT_FORMAT} > ${OUTPUT_FILE}"
if [ -n "${INPUT_SERVER_URL}" ] && [ -n "${INPUT_API_KEY}" ]; then
  echo "[AIROM Action] Syncing AIBOM ledger to enterprise server: ${INPUT_SERVER_URL}"
fi

# Run scan
eval "${SCAN_CMD}" || {
  SCAN_EXIT_CODE=$?
  echo "::warning::AIROM scan exited with code ${SCAN_EXIT_CODE}"
}

# Generate Table summary for PR Comment / Job Summary
SUMMARY_FILE="airom-summary.md"
airom scan "${SCAN_PATH}" -o table > "${SUMMARY_FILE}" 2>/dev/null || true

# Append to GitHub Step Summary if available
if [ -n "${GITHUB_STEP_SUMMARY}" ] && [ -f "${SUMMARY_FILE}" ]; then
  echo "### 🛡️ AIROM AI Governance & Security Scan Results" >> "${GITHUB_STEP_SUMMARY}"
  echo '```' >> "${GITHUB_STEP_SUMMARY}"
  cat "${SUMMARY_FILE}" >> "${GITHUB_STEP_SUMMARY}"
  echo '```' >> "${GITHUB_STEP_SUMMARY}"
fi

# Post PR Comment if enabled and in a Pull Request context
if [ "${INPUT_POST_PR_COMMENT}" = "true" ] && [ -n "${GITHUB_EVENT_PATH}" ] && [ -f "${GITHUB_EVENT_PATH}" ]; then
  PR_NUMBER=$(jq -r '.pull_request.number // empty' "${GITHUB_EVENT_PATH}" || true)
  if [ -n "${PR_NUMBER}" ] && [ -n "${INPUT_GITHUB_TOKEN}" ]; then
    echo "[AIROM Action] Posting governance report comment to PR #${PR_NUMBER}..."
    COMMENT_BODY=$(cat <<EOF
### 🛡️ AIROM AI Governance & Security Report

**Target Path:** \`${SCAN_PATH}\`
**Policy Level:** \`${POLICY}\`

\`\`\`
$(cat "${SUMMARY_FILE}")
\`\`\`

*Automated governance check performed by [AIROM](https://github.com/airomhq/airom).*
EOF
)
    PAYLOAD=$(jq -n --arg body "${COMMENT_BODY}" '{body: $body}')
    curl -s -X POST \
      -H "Authorization: token ${INPUT_GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
      -d "${PAYLOAD}" > /dev/null || echo "::warning::Failed to post PR comment"
  fi
fi

echo "[AIROM Action] Scan completed successfully."
