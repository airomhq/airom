package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRBAC_PermissionMatrix_Completeness(t *testing.T) {
	// Admin has all permissions
	adminPerms := GetRolePermissions(RoleAdmin)
	if len(adminPerms) != 8 {
		t.Errorf("expected 8 permissions for Admin, got %d", len(adminPerms))
	}
	if !HasPermission(RoleAdmin, PermOrgManage) || !HasPermission(RoleAdmin, PermDocumentCertify) {
		t.Errorf("Admin missing required permissions")
	}

	// ComplianceOfficer has certification + report + audit + ledger
	coPerms := GetRolePermissions(RoleComplianceOfficer)
	if len(coPerms) != 4 {
		t.Errorf("expected 4 permissions for ComplianceOfficer, got %d", len(coPerms))
	}
	if !HasPermission(RoleComplianceOfficer, PermDocumentCertify) || HasPermission(RoleComplianceOfficer, PermOrgManage) {
		t.Errorf("ComplianceOfficer permission mismatch")
	}

	// Developer has scan + report + ledger
	devPerms := GetRolePermissions(RoleDeveloper)
	if len(devPerms) != 3 {
		t.Errorf("expected 3 permissions for Developer, got %d", len(devPerms))
	}
	if !HasPermission(RoleDeveloper, PermScanWrite) || HasPermission(RoleDeveloper, PermDocumentCertify) {
		t.Errorf("Developer permission mismatch")
	}

	// Auditor has audit + ledger only
	auditorPerms := GetRolePermissions(RoleAuditor)
	if len(auditorPerms) != 2 {
		t.Errorf("expected 2 permissions for Auditor, got %d", len(auditorPerms))
	}
	if !HasPermission(RoleAuditor, PermAuditRead) || HasPermission(RoleAuditor, PermScanWrite) {
		t.Errorf("Auditor permission mismatch")
	}
}

func TestRBAC_RoleValidation_Rejection(t *testing.T) {
	if err := ValidateRole("SUPERUSER"); err == nil {
		t.Errorf("expected error on invalid role SUPERUSER")
	}
	if err := ValidateRole(RoleAdmin); err != nil {
		t.Errorf("unexpected error on valid role: %v", err)
	}
}

func TestToken_SessionTokenLifecycle(t *testing.T) {
	secret := []byte("test-auth-secret-32bytes-long-key")
	user := User{
		ID:    "usr-01",
		OrgID: "org-acme",
		Email: "alice@acme.com",
		Role:  RoleAdmin,
	}

	tokenStr, claims, err := IssueSessionToken(secret, user, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to issue session token: %v", err)
	}

	parsed, err := VerifySessionToken(secret, tokenStr)
	if err != nil {
		t.Fatalf("failed to verify session token: %v", err)
	}

	if parsed.UserID != user.ID || parsed.OrgID != user.OrgID || parsed.Role != RoleAdmin {
		t.Errorf("token payload mismatch: %+v vs %+v", parsed, claims)
	}
}

func TestToken_ExpiredAndTampered_FailsClosed(t *testing.T) {
	secret := []byte("test-auth-secret-32bytes-long-key")
	user := User{
		ID:    "usr-01",
		OrgID: "org-acme",
		Role:  RoleDeveloper,
	}

	// 1. Expired Token
	tokenStr, _, _ := IssueSessionToken(secret, user, 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	_, err := VerifySessionToken(secret, tokenStr)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected token expired error, got: %v", err)
	}

	// 2. Tampered Token
	validToken, _, _ := IssueSessionToken(secret, user, 1*time.Hour)
	_, err = VerifySessionToken(secret, validToken+"tampered")
	if err == nil || !strings.Contains(err.Error(), "invalid or tampered") {
		t.Errorf("expected signature invalid error, got: %v", err)
	}
}

func TestAPIKey_MintAndAuthenticate(t *testing.T) {
	orgID := "org-acme"
	rawKey, apiKey, err := MintAPIKey(orgID, "CI Scanner Key", RoleDeveloper, nil)
	if err != nil {
		t.Fatalf("failed to mint api key: %v", err)
	}

	if !strings.HasPrefix(rawKey, "airom_live_") {
		t.Errorf("expected airom_live_ prefix in raw key: %s", rawKey)
	}

	storedKeys := []APIKey{apiKey}

	// Authenticate valid key
	matched, claims, err := AuthenticateAPIKey(rawKey, storedKeys)
	if err != nil {
		t.Fatalf("failed to authenticate api key: %v", err)
	}
	if matched.ID != apiKey.ID || claims.OrgID != orgID || claims.Role != RoleDeveloper {
		t.Errorf("api key authentication mismatch: %+v", claims)
	}

	// Revoke key
	apiKey.IsActive = false
	storedKeys = []APIKey{apiKey}
	_, _, err = AuthenticateAPIKey(rawKey, storedKeys)
	if err != ErrKeyInactive {
		t.Errorf("expected ErrKeyInactive, got: %v", err)
	}
}

func TestHTTP_SSO_And_RBAC_Protection(t *testing.T) {
	secret := []byte("test-http-auth-secret-32bytes-k")
	svc := NewService(secret)
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	// 1. SSO Callback -> Issues JWT for Admin
	ssoPayload := map[string]string{
		"org_id":       "org-corp",
		"email":        "admin@corp.com",
		"name":         "Admin Alice",
		"sso_provider": "Okta",
		"role":         "ADMIN",
	}
	sBody, _ := json.Marshal(ssoPayload)
	resp1, err := http.Post(ts.URL+"/api/v1/auth/sso/callback", "application/json", bytes.NewReader(sBody))
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("SSO callback failed: %v", err)
	}

	var authRes map[string]interface{}
	json.NewDecoder(resp1.Body).Decode(&authRes)
	resp1.Body.Close()
	adminToken := authRes["token"].(string)

	// 2. Admin Mints API Key
	keyPayload := map[string]interface{}{
		"name": "GitHub Actions Key",
		"role": "DEVELOPER",
	}
	kBody, _ := json.Marshal(keyPayload)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/keys", bytes.NewReader(kBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp2, err := client.Do(req)
	if err != nil || resp2.StatusCode != http.StatusCreated {
		t.Fatalf("mint key failed: %v", err)
	}

	var keyRes map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&keyRes)
	resp2.Body.Close()
	rawAPIKey := keyRes["raw_api_key"].(string)

	// 3. Developer SSO Callback
	devPayload := map[string]string{
		"org_id":       "org-corp",
		"email":        "dev@corp.com",
		"name":         "Developer Bob",
		"sso_provider": "Okta",
		"role":         "DEVELOPER",
	}
	dBody, _ := json.Marshal(devPayload)
	resp3, _ := http.Post(ts.URL+"/api/v1/auth/sso/callback", "application/json", bytes.NewReader(dBody))
	var devAuthRes map[string]interface{}
	json.NewDecoder(resp3.Body).Decode(&devAuthRes)
	resp3.Body.Close()
	devToken := devAuthRes["token"].(string)

	// 4. Developer attempts Admin-only action (Mint API Key) -> FORBIDDEN (403)
	req4, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/keys", bytes.NewReader(kBody))
	req4.Header.Set("Authorization", "Bearer "+devToken)
	req4.Header.Set("Content-Type", "application/json")
	resp4, err := client.Do(req4)
	if err != nil || resp4.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for Developer on Admin route, got: %d", resp4.StatusCode)
	}
	resp4.Body.Close()

	// 5. Test API Key Authentication on Authenticate()
	testReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/keys", nil)
	testReq.Header.Set("Authorization", "Bearer "+rawAPIKey)
	claims, err := svc.Authenticate(testReq)
	if err != nil || claims.Role != RoleDeveloper || claims.TokenType != "api_key" {
		t.Errorf("failed to authenticate raw API key: %v, claims=%+v", err, claims)
	}
}

func TestHTTP_UserProvisioning_RoleUpdate_AuditLogs(t *testing.T) {
	secret := []byte("test-http-auth-secret-32bytes-k")
	svc := NewService(secret)
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := &http.Client{}

	// 1. Admin Login
	ssoPayload := map[string]string{
		"org_id":       "org-alpha",
		"email":        "admin@alpha.com",
		"name":         "Admin Alpha",
		"sso_provider": "AzureAD",
		"role":         "ADMIN",
	}
	sBody, _ := json.Marshal(ssoPayload)
	resp, _ := http.Post(ts.URL+"/api/v1/auth/sso/callback", "application/json", bytes.NewReader(sBody))
	var authRes map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&authRes)
	adminToken := authRes["token"].(string)

	// 2. Admin Provisions New User
	newUser := map[string]string{
		"email": "auditor@alpha.com",
		"name":  "Auditor Charlie",
		"role":  "AUDITOR",
	}
	uBody, _ := json.Marshal(newUser)
	uReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/users", bytes.NewReader(uBody))
	uReq.Header.Set("Authorization", "Bearer "+adminToken)
	uReq.Header.Set("Content-Type", "application/json")
	uResp, err := client.Do(uReq)
	if err != nil || uResp.StatusCode != http.StatusCreated {
		t.Fatalf("provision user failed: %v", err)
	}
	var createdUser User
	json.NewDecoder(uResp.Body).Decode(&createdUser)
	uResp.Body.Close()

	if createdUser.Role != RoleAuditor || createdUser.Email != "auditor@alpha.com" {
		t.Errorf("unexpected created user: %+v", createdUser)
	}

	// 3. Admin Updates User Role to ComplianceOfficer
	roleUpdate := map[string]string{"role": "COMPLIANCE_OFFICER"}
	rBody, _ := json.Marshal(roleUpdate)
	rReq, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/auth/users/%s/role", ts.URL, createdUser.ID), bytes.NewReader(rBody))
	rReq.Header.Set("Authorization", "Bearer "+adminToken)
	rReq.Header.Set("Content-Type", "application/json")
	rResp, err := client.Do(rReq)
	if err != nil || rResp.StatusCode != http.StatusOK {
		t.Fatalf("update role failed: %v", err)
	}
	var updatedUser User
	json.NewDecoder(rResp.Body).Decode(&updatedUser)
	rResp.Body.Close()

	if updatedUser.Role != RoleComplianceOfficer {
		t.Errorf("expected COMPLIANCE_OFFICER, got: %s", updatedUser.Role)
	}

	// 4. Query Auth Audit Logs
	aReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/auth/audit", nil)
	aReq.Header.Set("Authorization", "Bearer "+adminToken)
	aResp, err := client.Do(aReq)
	if err != nil || aResp.StatusCode != http.StatusOK {
		t.Fatalf("get audit logs failed: %v", err)
	}
	var logs []AuthEvent
	json.NewDecoder(aResp.Body).Decode(&logs)
	aResp.Body.Close()

	if len(logs) < 3 {
		t.Errorf("expected at least 3 audit log events, got %d", len(logs))
	}
}

func TestAuthorizeOrg_MultiTenantIsolation(t *testing.T) {
	claims := &AuthClaims{
		UserID: "usr-1",
		OrgID:  "org-tenant-a",
		Role:   RoleAdmin,
	}

	if err := AuthorizeOrg(claims, "org-tenant-a"); err != nil {
		t.Errorf("expected matching org to authorize, got: %v", err)
	}

	if err := AuthorizeOrg(claims, "org-tenant-b"); err != ErrOrgMismatch && !strings.Contains(err.Error(), "cross-organization") {
		t.Errorf("expected ErrOrgMismatch on foreign org, got: %v", err)
	}
}

func BenchmarkAuth_SessionVerification(b *testing.B) {
	secret := []byte("bench-auth-secret-32bytes-long-key")
	user := User{
		ID:    "usr-bench",
		OrgID: "org-bench",
		Role:  RoleAdmin,
	}
	tokenStr, _, _ := IssueSessionToken(secret, user, 24*time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifySessionToken(secret, tokenStr)
	}
}

func BenchmarkAuth_APIKeyAuthentication(b *testing.B) {
	rawKey, apiKey, _ := MintAPIKey("org-bench", "Bench Key", RoleDeveloper, nil)
	storedKeys := []APIKey{apiKey}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = AuthenticateAPIKey(rawKey, storedKeys)
	}
}
