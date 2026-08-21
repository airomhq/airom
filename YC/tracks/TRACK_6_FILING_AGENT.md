# Track 6: FilingAgent & Human-in-the-Loop Gateway

> **Ownership:** Fullstack Product Engineer & Legal Systems Architect  
> **Key Focus:** State Portal Adapters (REST/PDF/Email), Green/Yellow/Red Review UI, 90s HMAC Token Gate, Immutable Audit Trail.

---

## 1. Scope & Technical Objectives

1. **Strict Human-in-the-Loop Architecture:** Machine pre-fills and validates; human certifies and clicks submit. No automated submission path exists.
2. **Green / Yellow / Red Filing UI:** 
   - **Green:** Machine-verified from AIBOM (locked).
   - **Yellow:** Human attestation required (blocks submit until answered).
   - **Red:** Compliance gap (blocks submit unless explicitly acknowledged with documented rationale).
3. **State Portal Adapters:** Pluggable connector architecture for Colorado AG API, NYC LL144 email dispatch, and California CPPA portal.
4. **Append-Only Submission Ledger:** Cryptographically signed audit record with user identity, timestamp, and portal confirmation numbers.

---

## 2. Sprint Backlog & Epics (Months 9–12)

### Epic T6.1: Pluggable Filing Adapters (Sprint 18–21)
- [ ] Implement FilingAdapter base interface with prepare(), alidate(), and submit() methods.
- [ ] RestApiAdapter: Colorado AI Act AG portal connector with OAuth2 credentials.
- [ ] PdfFormFillAdapter: Automated fill of state government PDF application forms.
- [ ] EmailDispatchAdapter: Signed SMTP / SendGrid dispatch with PDF attachments and BCC archiving.

### Epic T6.2: Green/Yellow/Red Filing Review UI (Sprint 20–24)
- [ ] Interactive review screen wireframe implementation in React / Next.js.
- [ ] Real-time validation state calculator (unlocks Submit button only when all conditions met).
- [ ] 90-Second ephemeral HMAC human_confirmation_token generation on modal confirmation.

### Epic T6.3: Immutable Filing Audit Log (Sprint 22–25)
- [ ] PostgreSQL append-only audit table with REVOKE UPDATE, DELETE permissions.
- [ ] Exportable filing certificate PDF including portal response and hash of evidence AIBOM.

---

## 3. Definition of Done (DoD)
- Zero automated submission paths verified by CI grep guardrails.
- Submit button physically locked when any Yellow section is unanswered.
- Every successful filing logs an immutable record with portal confirmation ID.
