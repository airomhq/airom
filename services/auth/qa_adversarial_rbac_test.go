package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// helper to ensure HTTP connections are properly drained and returned to pool
func drainAndClose(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func newTestClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
		},
		Timeout: 10 * time.Second,
	}
}

// ============================================================================
// TEST 1: Privilege Escalation Matrix
// ============================================================================

func TestQA_PrivilegeEscalationMatrix(t *testing.T) {
	secret := []byte("qa-adversarial-rbac-secret-key-32bytes!")
	svc := NewService(secret)
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()
	client := newTestClient()

	allRoles := []Role{RoleAdmin, RoleComplianceOfficer, RoleDeveloper, RoleAuditor}
	allPerms := []Permission{
		PermOrgManage,
		PermUserManage,
		PermKeyRotate,
		PermScanWrite,
		PermReportGenerate,
		PermDocumentCertify,
		PermAuditRead,
		PermLedgerVerify,
	}

	// ------------------------------------------------------------------------
	// Subtest 1.1: Direct RBAC Authorization Matrix Verification
	// ------------------------------------------------------------------------
	t.Run("RBAC_DirectMatrix_Rejection", func(t *testing.T) {
		for _, role := range allRoles {
			for _, perm := range allPerms {
				expectedAllowed := HasPermission(role, perm)
				claims := &AuthClaims{
					UserID:      fmt.Sprintf("usr-%s", role),
					OrgID:       "org-security-matrix",
					Role:        role,
					Permissions: GetRolePermissions(role),
				}

				err := Authorize(claims, perm)
				if expectedAllowed {
					if err != nil {
						t.Errorf("Role %s SHOULD hold perm %s, but Authorize returned error: %v", role, perm, err)
					}
				} else {
					if err == nil {
						t.Errorf("SECURITY BREACH: Role %s was ALLOWED unauthorized perm %s", role, perm)
					}
					if !strings.Contains(err.Error(), "forbidden: insufficient role permissions") {
						t.Errorf("Role %s unauthorized perm %s returned unexpected error message: %v", role, perm, err)
					}
				}
			}
		}

		// Verify unauthenticated (nil claims)
		for _, perm := range allPerms {
			if err := Authorize(nil, perm); err != ErrUnauthorized {
				t.Errorf("SECURITY BREACH: Nil claims Authorize(%s) did not return ErrUnauthorized: %v", perm, err)
			}
		}
	})

	// ------------------------------------------------------------------------
	// Subtest 1.2: Auditor Privilege Escalation Attempts
	// ------------------------------------------------------------------------
	t.Run("Auditor_Escalation_Blocked", func(t *testing.T) {
		auditorUser := User{
			ID:    "usr-auditor-01",
			OrgID: "org-matrix-qa",
			Email: "auditor@qa.airom.internal",
			Role:  RoleAuditor,
		}
		auditorToken, _, err := IssueSessionToken(secret, auditorUser, 1*time.Hour)
		if err != nil {
			t.Fatalf("failed to issue auditor token: %v", err)
		}

		// Attack 1.2.1: Auditor attempts to mint API Key (PermKeyRotate)
		keyBody, _ := json.Marshal(map[string]string{"name": "Auditor Forged Key", "role": "ADMIN"})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/keys", bytes.NewReader(keyBody))
		req.Header.Set("Authorization", "Bearer "+auditorToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Auditor mint key returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.2.2: Auditor attempts to create/provision users (PermUserManage)
		userBody, _ := json.Marshal(map[string]string{"email": "newadmin@qa.airom.internal", "role": "ADMIN"})
		req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/users", bytes.NewReader(userBody))
		req.Header.Set("Authorization", "Bearer "+auditorToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Auditor create user returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.2.3: Auditor attempts to promote a user to Admin (PermUserManage)
		roleBody, _ := json.Marshal(map[string]string{"role": "ADMIN"})
		req, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/v1/auth/users/usr-target/role", bytes.NewReader(roleBody))
		req.Header.Set("Authorization", "Bearer "+auditorToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Auditor role promotion returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.2.4: Auditor attempts to delete/revoke API Key (PermKeyRotate)
		req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/auth/keys/key-some-id", nil)
		req.Header.Set("Authorization", "Bearer "+auditorToken)
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Auditor delete key returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.2.5: Auditor attempts document certify (PermDocumentCertify) via RequirePermission
		certifyHandler := svc.RequirePermission(PermDocumentCertify, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodPost, "/certify", nil)
		req.Header.Set("Authorization", "Bearer "+auditorToken)
		certifyHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Auditor certify doc returned %d (expected 403 Forbidden)", rec.Code)
		}
	})

	// ------------------------------------------------------------------------
	// Subtest 1.3: Developer Privilege Escalation Attempts
	// ------------------------------------------------------------------------
	t.Run("Developer_Escalation_Blocked", func(t *testing.T) {
		devUser := User{
			ID:    "usr-dev-01",
			OrgID: "org-matrix-qa",
			Email: "developer@qa.airom.internal",
			Role:  RoleDeveloper,
		}
		devToken, _, err := IssueSessionToken(secret, devUser, 1*time.Hour)
		if err != nil {
			t.Fatalf("failed to issue developer token: %v", err)
		}

		// Attack 1.3.1: Developer attempts to mint API Key
		keyBody, _ := json.Marshal(map[string]string{"name": "Dev Escaped Key", "role": "ADMIN"})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/keys", bytes.NewReader(keyBody))
		req.Header.Set("Authorization", "Bearer "+devToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Developer mint key returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.3.2: Developer attempts to delete/revoke API Key
		req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/auth/keys/key-test", nil)
		req.Header.Set("Authorization", "Bearer "+devToken)
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Developer delete key returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.3.3: Developer attempts to create users
		userBody, _ := json.Marshal(map[string]string{"email": "devadmin@qa.airom.internal", "role": "ADMIN"})
		req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/users", bytes.NewReader(userBody))
		req.Header.Set("Authorization", "Bearer "+devToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Developer create user returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.3.4: Developer attempts to promote own role to ADMIN
		roleBody, _ := json.Marshal(map[string]string{"role": "ADMIN"})
		req, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/v1/auth/users/usr-dev-01/role", bytes.NewReader(roleBody))
		req.Header.Set("Authorization", "Bearer "+devToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Developer self-promotion returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.3.5: Developer attempts to access Audit Logs (PermAuditRead)
		req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/audit", nil)
		req.Header.Set("Authorization", "Bearer "+devToken)
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Developer read audit logs returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.3.6: Developer attempts Document Certification (PermDocumentCertify)
		certifyHandler := svc.RequirePermission(PermDocumentCertify, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodPost, "/certify", nil)
		req.Header.Set("Authorization", "Bearer "+devToken)
		certifyHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: Developer certify doc returned %d (expected 403 Forbidden)", rec.Code)
		}
	})

	// ------------------------------------------------------------------------
	// Subtest 1.4: Compliance Officer Privilege Boundary Enforcement
	// ------------------------------------------------------------------------
	t.Run("ComplianceOfficer_Escalation_Blocked", func(t *testing.T) {
		coUser := User{
			ID:    "usr-co-01",
			OrgID: "org-matrix-qa",
			Email: "compliance@qa.airom.internal",
			Role:  RoleComplianceOfficer,
		}
		coToken, _, err := IssueSessionToken(secret, coUser, 1*time.Hour)
		if err != nil {
			t.Fatalf("failed to issue compliance officer token: %v", err)
		}

		// Attack 1.4.1: Compliance Officer attempts to manage organization settings (PermOrgManage)
		orgManageHandler := svc.RequirePermission(PermOrgManage, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/org/settings", nil)
		req.Header.Set("Authorization", "Bearer "+coToken)
		orgManageHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: ComplianceOfficer manage org returned %d (expected 403 Forbidden)", rec.Code)
		}

		// Attack 1.4.2: Compliance Officer attempts to manage users (PermUserManage)
		userBody, _ := json.Marshal(map[string]string{"email": "coadmin@qa.airom.internal", "role": "ADMIN"})
		req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/users", bytes.NewReader(userBody))
		req.Header.Set("Authorization", "Bearer "+coToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: ComplianceOfficer create user returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.4.3: Compliance Officer attempts to mint API Key (PermKeyRotate)
		keyBody, _ := json.Marshal(map[string]string{"name": "CO Key", "role": "ADMIN"})
		req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/keys", bytes.NewReader(keyBody))
		req.Header.Set("Authorization", "Bearer "+coToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: ComplianceOfficer mint key returned %d (expected 403 Forbidden)", resp.StatusCode)
		}

		// Attack 1.4.4: Compliance Officer attempts to write scan data (PermScanWrite)
		scanWriteHandler := svc.RequirePermission(PermScanWrite, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		rec = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodPost, "/scan/write", nil)
		req.Header.Set("Authorization", "Bearer "+coToken)
		scanWriteHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("SECURITY BREACH: ComplianceOfficer write scan returned %d (expected 403 Forbidden)", rec.Code)
		}
	})

	// ------------------------------------------------------------------------
	// Subtest 1.5: Unauthenticated Access to All Protected Endpoints
	// ------------------------------------------------------------------------
	t.Run("Unauthenticated_Requests_FailClosed_401", func(t *testing.T) {
		unprotectedRoutes := []struct {
			method string
			path   string
		}{
			{http.MethodPost, "/api/v1/auth/keys"},
			{http.MethodGet, "/api/v1/auth/keys"},
			{http.MethodDelete, "/api/v1/auth/keys/key-dummy-id"},
			{http.MethodPost, "/api/v1/auth/users"},
			{http.MethodGet, "/api/v1/auth/users"},
			{http.MethodPut, "/api/v1/auth/users/usr-dummy-id/role"},
			{http.MethodGet, "/api/v1/auth/audit"},
		}

		for _, route := range unprotectedRoutes {
			// Case A: No Authorization Header
			req, _ := http.NewRequest(route.method, ts.URL+route.path, bytes.NewReader([]byte(`{"role":"ADMIN"}`)))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			drainAndClose(resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("SECURITY BREACH: Anonymous %s %s returned %d (expected 401 Unauthorized)", route.method, route.path, resp.StatusCode)
			}

			// Case B: Garbage Bearer Token
			reqGarbage, _ := http.NewRequest(route.method, ts.URL+route.path, bytes.NewReader([]byte(`{"role":"ADMIN"}`)))
			reqGarbage.Header.Set("Authorization", "Bearer invalid.garbage.token")
			reqGarbage.Header.Set("Content-Type", "application/json")
			respG, err := client.Do(reqGarbage)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			drainAndClose(respG)
			if respG.StatusCode != http.StatusUnauthorized {
				t.Errorf("SECURITY BREACH: Garbage token %s %s returned %d (expected 401 Unauthorized)", route.method, route.path, respG.StatusCode)
			}
		}
	})
}

// ============================================================================
// TEST 2: Adversarial Token Attacks (Signature Tampering, Forgery, Replay)
// ============================================================================

func TestQA_AdversarialTokenAttacks(t *testing.T) {
	secret := []byte("qa-token-defense-master-secret-32b-key!")
	svc := NewService(secret)
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()
	client := newTestClient()

	victimUser := User{
		ID:    "usr-victim-99",
		OrgID: "org-victim-corp",
		Email: "victim@victimcorp.com",
		Role:  RoleDeveloper,
	}

	validToken, _, err := IssueSessionToken(secret, victimUser, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to issue valid token: %v", err)
	}

	parts := strings.Split(validToken, ".")
	if len(parts) != 2 {
		t.Fatalf("invalid token format: %s", validToken)
	}
	payloadB64 := parts[0]
	hexSig := parts[1]

	// ------------------------------------------------------------------------
	// Attack 2.1: Signature Bit-Flipping Attacks
	// ------------------------------------------------------------------------
	t.Run("Signature_BitFlipping_Defense", func(t *testing.T) {
		sigBytes := []byte(hexSig)
		for i := 0; i < len(sigBytes); i++ {
			// Flip hex character
			tamperedSig := make([]byte, len(sigBytes))
			copy(tamperedSig, sigBytes)
			if tamperedSig[i] == 'a' {
				tamperedSig[i] = 'b'
			} else {
				tamperedSig[i] = 'a'
			}

			tamperedToken := fmt.Sprintf("%s.%s", payloadB64, string(tamperedSig))

			// Direct Verification (Exhaustive across all bit positions)
			_, err := VerifySessionToken(secret, tamperedToken)
			if err != ErrTokenInvalidSig {
				t.Errorf("SECURITY FAILURE: Bit-flipped token at offset %d did not return ErrTokenInvalidSig: %v", i, err)
			}

			// HTTP Boundary Verification on sample offsets
			if i%8 == 0 {
				req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/audit", nil)
				req.Header.Set("Authorization", "Bearer "+tamperedToken)
				resp, errHTTP := client.Do(req)
				if errHTTP != nil {
					t.Fatalf("request failed: %v", errHTTP)
				}
				drainAndClose(resp)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("SECURITY BREACH: Bit-flipped token admitted into HTTP endpoint with status %d", resp.StatusCode)
				}
			}
		}
	})

	// ------------------------------------------------------------------------
	// Attack 2.2: Secret Key Bruteforce & Weak Secret Forgery
	// ------------------------------------------------------------------------
	t.Run("Weak_Secret_Bruteforce_Defense", func(t *testing.T) {
		weakKeys := [][]byte{
			[]byte("secret"),
			[]byte("123456"),
			[]byte("password"),
			[]byte("admin"),
			[]byte("airom"),
			[]byte("jwtsecret"),
			[]byte("test"),
			[]byte("12345678901234567890123456789012"),
		}

		adminUser := User{
			ID:    "usr-attacker-admin",
			OrgID: "org-victim-corp",
			Email: "attacker@forged.com",
			Role:  RoleAdmin,
		}

		for _, weakKey := range weakKeys {
			forgedToken, _, err := IssueSessionToken(weakKey, adminUser, 24*time.Hour)
			if err != nil {
				t.Fatalf("failed to issue forged token: %v", err)
			}

			// Must be rejected by service using genuine secret
			claims, err := VerifySessionToken(secret, forgedToken)
			if err != ErrTokenInvalidSig || claims != nil {
				t.Fatalf("CRITICAL SECURITY BREACH: Token signed with weak key %q accepted by service!", string(weakKey))
			}

			// Verify rejection at HTTP layer
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/keys", nil)
			req.Header.Set("Authorization", "Bearer "+forgedToken)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			drainAndClose(resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("CRITICAL SECURITY BREACH: Weak key token admitted to API with HTTP %d", resp.StatusCode)
			}
		}
	})

	// ------------------------------------------------------------------------
	// Attack 2.3: Cross-Tenant Org Claim Spoofing
	// ------------------------------------------------------------------------
	t.Run("CrossTenant_OrgClaim_Spoofing_Defense", func(t *testing.T) {
		rawPayloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
		if err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}

		var claims AuthClaims
		if err := json.Unmarshal(rawPayloadBytes, &claims); err != nil {
			t.Fatalf("failed to unmarshal claims: %v", err)
		}

		// Attacker modifies org_id and elevates role to ADMIN in payload
		claims.OrgID = "org-target-enterprise"
		claims.Role = RoleAdmin
		claims.Permissions = GetRolePermissions(RoleAdmin)

		tamperedPayloadJSON, _ := json.Marshal(claims)
		tamperedPayloadB64 := base64.RawURLEncoding.EncodeToString(tamperedPayloadJSON)

		// Attack with original signature (signature mismatch)
		spoofedToken := fmt.Sprintf("%s.%s", tamperedPayloadB64, hexSig)
		_, err = VerifySessionToken(secret, spoofedToken)
		if err != ErrTokenInvalidSig {
			t.Fatalf("SECURITY BREACH: Claim-spoofed token bypassed signature verification: %v", err)
		}

		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/audit", nil)
		req.Header.Set("Authorization", "Bearer "+spoofedToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("SECURITY BREACH: Spoofed claim token admitted to HTTP endpoint with status %d", resp.StatusCode)
		}
	})

	// ------------------------------------------------------------------------
	// Attack 2.4: Expired Token Replay Attacks
	// ------------------------------------------------------------------------
	t.Run("ExpiredToken_Replay_Defense", func(t *testing.T) {
		// Mint short-lived token (1 millisecond TTL)
		shortLivedToken, _, err := IssueSessionToken(secret, victimUser, 1*time.Millisecond)
		if err != nil {
			t.Fatalf("failed to mint short-lived token: %v", err)
		}

		// Wait for token to expire
		time.Sleep(15 * time.Millisecond)

		// Verification must fail closed with expiration error
		claims, err := VerifySessionToken(secret, shortLivedToken)
		if err == nil || !strings.Contains(err.Error(), "expired") || claims != nil {
			t.Fatalf("SECURITY BREACH: Expired token accepted! Error: %v, Claims: %+v", err, claims)
		}

		// Verify HTTP rejection
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/keys", nil)
		req.Header.Set("Authorization", "Bearer "+shortLivedToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("SECURITY BREACH: Expired token accepted by HTTP gateway with status %d", resp.StatusCode)
		}
	})

	// ------------------------------------------------------------------------
	// Attack 2.5: Malformed Base64 & Structural Token Corruption
	// ------------------------------------------------------------------------
	t.Run("Malformed_Structure_Defense", func(t *testing.T) {
		malformedTokens := []struct {
			name  string
			token string
		}{
			{"no_separator", "payloadWithoutSeparatingDotAndSignature"},
			{"three_parts_jwt", "header.payload.signature"},
			{"four_parts", "part1.part2.part3.part4"},
			{"leading_dot", ".hexsignatureonly"},
			{"trailing_dot", "payloadb64only."},
			{"double_dot", "payload..signature"},
			{"corrupted_base64", "!@#$%^&*()." + hexSig},
			{"non_json_base64", base64.RawURLEncoding.EncodeToString([]byte("NOT_JSON_DATA")) + "." + hexSig},
			{"null_byte_injected", base64.RawURLEncoding.EncodeToString([]byte("{\"user_id\":\"1\x00\"}")) + "." + hexSig},
			{"truncated_base64", payloadB64[:len(payloadB64)/2] + "." + hexSig},
		}

		for _, tc := range malformedTokens {
			t.Run(tc.name, func(t *testing.T) {
				_, err := VerifySessionToken(secret, tc.token)
				if err == nil {
					t.Fatalf("SECURITY BREACH: Malformed token %q accepted!", tc.token)
				}

				req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/keys", nil)
				req.Header.Set("Authorization", "Bearer "+tc.token)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				drainAndClose(resp)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("SECURITY BREACH: Malformed token %q accepted with status %d", tc.name, resp.StatusCode)
				}
			})
		}
	})

	// ------------------------------------------------------------------------
	// Attack 2.6: Empty and Whitespace Token Injection
	// ------------------------------------------------------------------------
	t.Run("Empty_Whitespace_Injection_Defense", func(t *testing.T) {
		emptyCases := []string{
			"",
			" ",
			"   ",
			"\t",
			"\n",
			"\r\n",
			"  \t \n  ",
		}

		for _, emptyToken := range emptyCases {
			_, err := VerifySessionToken(secret, emptyToken)
			if err == nil {
				t.Fatalf("SECURITY BREACH: Empty/whitespace token %q accepted!", emptyToken)
			}

			// Authorization: Bearer <empty>
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/keys", nil)
			if emptyToken != "" {
				req.Header.Set("Authorization", "Bearer "+emptyToken)
			}
			resp, err := client.Do(req)
			if err == nil {
				drainAndClose(resp)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("SECURITY BREACH: Empty token header accepted with status %d", resp.StatusCode)
				}
			}

			// X-API-Key: <empty>
			reqAPIKey, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/keys", nil)
			reqAPIKey.Header.Set("X-API-Key", emptyToken)
			respK, errK := client.Do(reqAPIKey)
			if errK == nil {
				drainAndClose(respK)
				if respK.StatusCode != http.StatusUnauthorized {
					t.Errorf("SECURITY BREACH: Empty X-API-Key accepted with status %d", respK.StatusCode)
				}
			}
		}
	})
}

// ============================================================================
// TEST 3: Cross-Tenant Data Isolation (100 Tenant Scale Ingestion)
// ============================================================================

func TestQA_CrossTenantDataIsolation(t *testing.T) {
	secret := []byte("qa-cross-tenant-isolation-secret-32bytes!")
	svc := NewService(secret)
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()
	client := newTestClient()

	const numTenants = 100
	type tenantContext struct {
		orgID      string
		adminToken string
		devToken   string
		rawAPIKey  string
		apiKeyID   string
		userID     string
	}

	tenants := make([]tenantContext, numTenants)

	// ------------------------------------------------------------------------
	// Phase 1: Ingest 100 Tenant Organizations with Complete Resource Stacks
	// ------------------------------------------------------------------------
	for i := 0; i < numTenants; i++ {
		orgID := fmt.Sprintf("org-tenant-%03d", i+1)

		// 1. Ingest Admin via SSO Callback
		adminSSO := map[string]string{
			"org_id":       orgID,
			"email":        fmt.Sprintf("admin@%s.airom.internal", orgID),
			"name":         fmt.Sprintf("Admin %s", orgID),
			"sso_provider": "Okta",
			"role":         "ADMIN",
		}
		sBody, _ := json.Marshal(adminSSO)
		resp, err := client.Post(ts.URL+"/api/v1/auth/sso/callback", "application/json", bytes.NewReader(sBody))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("failed SSO setup for %s: %v", orgID, err)
		}
		var adminAuth map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&adminAuth)
		drainAndClose(resp)
		adminToken := adminAuth["token"].(string)

		// 2. Ingest Developer via SSO Callback
		devSSO := map[string]string{
			"org_id":       orgID,
			"email":        fmt.Sprintf("dev@%s.airom.internal", orgID),
			"name":         fmt.Sprintf("Dev %s", orgID),
			"sso_provider": "Okta",
			"role":         "DEVELOPER",
		}
		dBody, _ := json.Marshal(devSSO)
		respD, err := client.Post(ts.URL+"/api/v1/auth/sso/callback", "application/json", bytes.NewReader(dBody))
		if err != nil || respD.StatusCode != http.StatusOK {
			t.Fatalf("failed dev SSO setup for %s: %v", orgID, err)
		}
		var devAuth map[string]interface{}
		_ = json.NewDecoder(respD.Body).Decode(&devAuth)
		drainAndClose(respD)
		devToken := devAuth["token"].(string)

		// 3. Admin Provisions a Managed User
		newUserReq := map[string]string{
			"email": fmt.Sprintf("auditor@%s.airom.internal", orgID),
			"name":  fmt.Sprintf("Auditor %s", orgID),
			"role":  "AUDITOR",
		}
		uBody, _ := json.Marshal(newUserReq)
		reqU, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/users", bytes.NewReader(uBody))
		reqU.Header.Set("Authorization", "Bearer "+adminToken)
		reqU.Header.Set("Content-Type", "application/json")
		respU, err := client.Do(reqU)
		if err != nil || respU.StatusCode != http.StatusCreated {
			t.Fatalf("failed user provision for %s: %v", orgID, err)
		}
		var createdUser User
		_ = json.NewDecoder(respU.Body).Decode(&createdUser)
		drainAndClose(respU)

		// 4. Admin Mints an API Key
		newKeyReq := map[string]interface{}{
			"name": fmt.Sprintf("CI-Key-%s", orgID),
			"role": "DEVELOPER",
		}
		kBody, _ := json.Marshal(newKeyReq)
		reqK, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/keys", bytes.NewReader(kBody))
		reqK.Header.Set("Authorization", "Bearer "+adminToken)
		reqK.Header.Set("Content-Type", "application/json")
		respK, err := client.Do(reqK)
		if err != nil || respK.StatusCode != http.StatusCreated {
			t.Fatalf("failed key mint for %s: %v", orgID, err)
		}
		var keyRes map[string]interface{}
		_ = json.NewDecoder(respK.Body).Decode(&keyRes)
		drainAndClose(respK)

		rawKey := keyRes["raw_api_key"].(string)
		keyDetails := keyRes["key_details"].(map[string]interface{})
		keyID := keyDetails["id"].(string)

		tenants[i] = tenantContext{
			orgID:      orgID,
			adminToken: adminToken,
			devToken:   devToken,
			rawAPIKey:  rawKey,
			apiKeyID:   keyID,
			userID:     createdUser.ID,
		}
	}

	// ------------------------------------------------------------------------
	// Phase 2: Exhaustive Cross-Tenant Boundary Infiltration Tests
	// ------------------------------------------------------------------------
	t.Run("CrossTenant_Boundary_Infiltration_Attacks", func(t *testing.T) {
		for i := 0; i < numTenants; i++ {
			victimIdx := (i + 1) % numTenants
			attacker := tenants[i]
			victim := tenants[victimIdx]

			// Attack 3.1: Attacker attempts to list Victim's Users
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/users", nil)
			req.Header.Set("Authorization", "Bearer "+attacker.adminToken)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			var returnedUsers []User
			_ = json.NewDecoder(resp.Body).Decode(&returnedUsers)
			drainAndClose(resp)

			for _, u := range returnedUsers {
				if u.OrgID != attacker.orgID {
					t.Fatalf("CRITICAL DATA LEAKAGE: Tenant %s received user %s from tenant %s!", attacker.orgID, u.Email, u.OrgID)
				}
			}

			// Attack 3.2: Attacker attempts to list Victim's API Keys
			reqK, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/keys", nil)
			reqK.Header.Set("Authorization", "Bearer "+attacker.adminToken)
			respK, err := client.Do(reqK)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			var returnedKeys []APIKey
			_ = json.NewDecoder(respK.Body).Decode(&returnedKeys)
			drainAndClose(respK)

			for _, k := range returnedKeys {
				if k.OrgID != attacker.orgID {
					t.Fatalf("CRITICAL DATA LEAKAGE: Tenant %s received API key %s from tenant %s!", attacker.orgID, k.Name, k.OrgID)
				}
			}

			// Attack 3.3: Attacker attempts to read Victim's Audit Logs
			reqA, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/audit", nil)
			reqA.Header.Set("Authorization", "Bearer "+attacker.adminToken)
			respA, err := client.Do(reqA)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			var returnedLogs []AuthEvent
			_ = json.NewDecoder(respA.Body).Decode(&returnedLogs)
			drainAndClose(respA)

			for _, e := range returnedLogs {
				if e.OrgID != attacker.orgID {
					t.Fatalf("CRITICAL DATA LEAKAGE: Tenant %s received Audit Event %s from tenant %s!", attacker.orgID, e.ID, e.OrgID)
				}
			}

			// Attack 3.4: Attacker attempts to modify Victim's User Role
			roleUpdateBody, _ := json.Marshal(map[string]string{"role": "ADMIN"})
			reqRole, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/auth/users/%s/role", ts.URL, victim.userID), bytes.NewReader(roleUpdateBody))
			reqRole.Header.Set("Authorization", "Bearer "+attacker.adminToken)
			reqRole.Header.Set("Content-Type", "application/json")
			respRole, err := client.Do(reqRole)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			drainAndClose(respRole)
			if respRole.StatusCode != http.StatusNotFound {
				t.Fatalf("SECURITY BREACH: Attacker %s modified user role for victim %s with status %d (expected 404 Not Found)", attacker.orgID, victim.userID, respRole.StatusCode)
			}

			// Attack 3.5: Attacker attempts to revoke Victim's API Key
			reqRevoke, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/auth/keys/%s", ts.URL, victim.apiKeyID), nil)
			reqRevoke.Header.Set("Authorization", "Bearer "+attacker.adminToken)
			respRevoke, err := client.Do(reqRevoke)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			drainAndClose(respRevoke)
			if respRevoke.StatusCode != http.StatusNotFound {
				t.Fatalf("SECURITY BREACH: Attacker %s revoked API key for victim %s with status %d (expected 404 Not Found)", attacker.orgID, victim.apiKeyID, respRevoke.StatusCode)
			}

			// Attack 3.6: AuthorizeOrg programmatic check across tenants
			attackerClaims := &AuthClaims{
				UserID: attacker.userID,
				OrgID:  attacker.orgID,
				Role:   RoleAdmin,
			}
			if err := AuthorizeOrg(attackerClaims, victim.orgID); err != ErrOrgMismatch && !strings.Contains(err.Error(), "cross-organization") {
				t.Fatalf("SECURITY BREACH: AuthorizeOrg allowed cross-tenant access between %s and %s: %v", attacker.orgID, victim.orgID, err)
			}
		}
	})

	// ------------------------------------------------------------------------
	// Phase 3: Cross-Tenant API Key Header Isolation
	// ------------------------------------------------------------------------
	t.Run("CrossTenant_APIKey_Isolation", func(t *testing.T) {
		for i := 0; i < numTenants; i++ {
			tCtx := tenants[i]

			// Authenticate using X-API-Key header
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/keys", nil)
			req.Header.Set("X-API-Key", tCtx.rawAPIKey)
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("API Key authentication failed for %s: %v (code %d)", tCtx.orgID, err, resp.StatusCode)
			}

			var keys []APIKey
			json.NewDecoder(resp.Body).Decode(&keys)
			drainAndClose(resp)

			for _, k := range keys {
				if k.OrgID != tCtx.orgID {
					t.Fatalf("CRITICAL DATA LEAKAGE: API Key for %s returned key belonging to %s!", tCtx.orgID, k.OrgID)
				}
			}
		}
	})
}

// ============================================================================
// TEST 4: Security Audit Trail Completeness & Immutability
// ============================================================================

func TestQA_SecurityAuditTrailCompleteness(t *testing.T) {
	secret := []byte("qa-audit-trail-completeness-secret-32b!")
	svc := NewService(secret)
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()
	client := newTestClient()

	orgID := "org-audit-verification"

	// ------------------------------------------------------------------------
	// Step 1: Trigger SSO Login Event
	// ------------------------------------------------------------------------
	ssoPayload := map[string]string{
		"org_id":       orgID,
		"email":        "admin@audit.airom.internal",
		"name":         "Audit Admin",
		"sso_provider": "AzureAD",
		"role":         "ADMIN",
	}
	sBody, _ := json.Marshal(ssoPayload)
	resp, err := client.Post(ts.URL+"/api/v1/auth/sso/callback", "application/json", bytes.NewReader(sBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("SSO callback failed: %v", err)
	}
	var authRes map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&authRes)
	drainAndClose(resp)
	adminToken := authRes["token"].(string)
	adminUserMap := authRes["user"].(map[string]interface{})
	adminUserID := adminUserMap["id"].(string)

	// ------------------------------------------------------------------------
	// Step 2: Trigger User Creation Event
	// ------------------------------------------------------------------------
	newUserPayload := map[string]string{
		"email": "dev@audit.airom.internal",
		"name":  "Audit Developer",
		"role":  "DEVELOPER",
	}
	uBody, _ := json.Marshal(newUserPayload)
	reqUser, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/users", bytes.NewReader(uBody))
	reqUser.Header.Set("Authorization", "Bearer "+adminToken)
	reqUser.Header.Set("Content-Type", "application/json")
	respU, err := client.Do(reqUser)
	if err != nil || respU.StatusCode != http.StatusCreated {
		t.Fatalf("User creation failed: %v", err)
	}
	var createdUser User
	json.NewDecoder(respU.Body).Decode(&createdUser)
	drainAndClose(respU)

	// ------------------------------------------------------------------------
	// Step 3: Trigger Role Change Event
	// ------------------------------------------------------------------------
	roleUpdatePayload := map[string]string{"role": "COMPLIANCE_OFFICER"}
	rBody, _ := json.Marshal(roleUpdatePayload)
	reqRole, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/auth/users/%s/role", ts.URL, createdUser.ID), bytes.NewReader(rBody))
	reqRole.Header.Set("Authorization", "Bearer "+adminToken)
	reqRole.Header.Set("Content-Type", "application/json")
	respR, err := client.Do(reqRole)
	if err != nil || respR.StatusCode != http.StatusOK {
		t.Fatalf("Role update failed: %v", err)
	}
	drainAndClose(respR)

	// ------------------------------------------------------------------------
	// Step 4: Trigger API Key Minting Event
	// ------------------------------------------------------------------------
	keyPayload := map[string]interface{}{
		"name": "Audit Test Key",
		"role": "DEVELOPER",
	}
	kBody, _ := json.Marshal(keyPayload)
	reqKey, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/keys", bytes.NewReader(kBody))
	reqKey.Header.Set("Authorization", "Bearer "+adminToken)
	reqKey.Header.Set("Content-Type", "application/json")
	respK, err := client.Do(reqKey)
	if err != nil || respK.StatusCode != http.StatusCreated {
		t.Fatalf("Key minting failed: %v", err)
	}
	var keyRes map[string]interface{}
	json.NewDecoder(respK.Body).Decode(&keyRes)
	drainAndClose(respK)
	keyDetails := keyRes["key_details"].(map[string]interface{})
	mintedKeyID := keyDetails["id"].(string)

	// ------------------------------------------------------------------------
	// Step 5: Trigger API Key Revocation Event
	// ------------------------------------------------------------------------
	reqRevoke, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/auth/keys/%s", ts.URL, mintedKeyID), nil)
	reqRevoke.Header.Set("Authorization", "Bearer "+adminToken)
	respRev, err := client.Do(reqRevoke)
	if err != nil || respRev.StatusCode != http.StatusOK {
		t.Fatalf("Key revocation failed: %v", err)
	}
	drainAndClose(respRev)

	// ------------------------------------------------------------------------
	// Step 6: Trigger Unauthorized Access / Permission Violation Event
	// ------------------------------------------------------------------------
	devUser := User{
		ID:    createdUser.ID,
		OrgID: orgID,
		Email: createdUser.Email,
		Role:  RoleDeveloper,
	}
	devToken, _, _ := IssueSessionToken(secret, devUser, 1*time.Hour)

	// Developer attempts Admin-restricted action wrapped with RequirePermission
	reqViolate, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/keys", bytes.NewReader(kBody))
	reqViolate.Header.Set("Authorization", "Bearer "+devToken)
	reqViolate.Header.Set("Content-Type", "application/json")
	respV, errV := client.Do(reqViolate)
	if errV != nil {
		t.Fatalf("request failed: %v", errV)
	}
	drainAndClose(respV)
	if respV.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for unauthorized access, got %d", respV.StatusCode)
	}

	// Developer attempts unauthorized custom action via RequirePermission handler
	adminOnlyHandler := svc.RequirePermission(PermOrgManage, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	reqSecCheck, _ := http.NewRequest(http.MethodPost, "/admin/system/configure", nil)
	reqSecCheck.Header.Set("Authorization", "Bearer "+devToken)
	adminOnlyHandler.ServeHTTP(rec, reqSecCheck)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden on custom RequirePermission route, got %d", rec.Code)
	}

	// ------------------------------------------------------------------------
	// Step 7: Verify Audit Trail Completeness and Exact Record Verification
	// ------------------------------------------------------------------------
	reqAudit, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/audit", nil)
	reqAudit.Header.Set("Authorization", "Bearer "+adminToken)
	respAudit, err := client.Do(reqAudit)
	if err != nil || respAudit.StatusCode != http.StatusOK {
		t.Fatalf("Failed to retrieve audit logs: %v", err)
	}
	var auditLogs []AuthEvent
	json.NewDecoder(respAudit.Body).Decode(&auditLogs)
	drainAndClose(respAudit)

	expectedEventTypes := []string{
		"SSO_LOGIN",
		"USER_CREATED",
		"ROLE_CHANGED",
		"KEY_MINTED",
		"KEY_REVOKED",
		"UNAUTHORIZED_ACCESS",
	}

	eventTypeCounts := make(map[string]int)
	for _, log := range auditLogs {
		// Strict Field Validations
		if log.ID == "" || !strings.HasPrefix(log.ID, "ev-") {
			t.Errorf("Audit log missing valid ID: %+v", log)
		}
		if log.OrgID != orgID {
			t.Errorf("Audit log contains mismatching OrgID %s (expected %s)", log.OrgID, orgID)
		}
		if log.UserID == "" {
			t.Errorf("Audit log missing UserID: %+v", log)
		}
		if log.EventType == "" {
			t.Errorf("Audit log missing EventType: %+v", log)
		}
		if log.Details == "" {
			t.Errorf("Audit log missing Details: %+v", log)
		}
		if log.Timestamp.IsZero() || time.Since(log.Timestamp) > 5*time.Minute {
			t.Errorf("Audit log has invalid or stale timestamp: %v", log.Timestamp)
		}

		eventTypeCounts[log.EventType]++
	}

	// Check each expected event type occurred at least once
	for _, expectedType := range expectedEventTypes {
		count := eventTypeCounts[expectedType]
		if count == 0 {
			t.Errorf("SECURITY AUDIT DEFICIENCY: Missing required audit event type %q in trail", expectedType)
		}
	}

	// Verify exact details for sensitive events
	foundRevoke := false
	foundViolation := false
	for _, log := range auditLogs {
		if log.EventType == "KEY_REVOKED" && strings.Contains(log.Details, mintedKeyID) {
			foundRevoke = true
			if log.UserID != adminUserID {
				t.Errorf("KEY_REVOKED UserID mismatch: expected %s, got %s", adminUserID, log.UserID)
			}
		}
		if log.EventType == "UNAUTHORIZED_ACCESS" && strings.Contains(log.Details, "org:manage") {
			foundViolation = true
			if log.UserID != createdUser.ID {
				t.Errorf("UNAUTHORIZED_ACCESS UserID mismatch: expected %s, got %s", createdUser.ID, log.UserID)
			}
		}
	}

	if !foundRevoke {
		t.Errorf("Audit trail did not record exact key ID %s in KEY_REVOKED event", mintedKeyID)
	}
	if !foundViolation {
		t.Errorf("Audit trail did not record exact permission in UNAUTHORIZED_ACCESS event")
	}
}
