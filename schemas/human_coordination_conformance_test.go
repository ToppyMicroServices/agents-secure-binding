// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const humanCoordinationConformanceSchemaV1 = "asb.human-coordination-conformance/v1"

type humanCoordinationConformanceManifest struct {
	Schema              string                                `json:"schema"`
	Scope               humanCoordinationConformanceScope     `json:"scope"`
	HumanAssurance      humanCoordinationHumanAssurance       `json:"human_assurance"`
	ProductionClaim     humanCoordinationProductionClaim      `json:"production_claim"`
	OperationBoundaries []humanCoordinationOperationBoundary  `json:"operation_boundaries"`
	Profiles            []humanCoordinationConformanceProfile `json:"profiles"`
}

type humanCoordinationHumanAssurance struct {
	CurrentProfile string                                 `json:"current_profile"`
	CurrentLevel   string                                 `json:"current_level"`
	Levels         []humanCoordinationHumanAssuranceLevel `json:"levels"`
	NonGuarantees  []string                               `json:"non_guarantees"`
}

type humanCoordinationHumanAssuranceLevel struct {
	ID          string                                `json:"id"`
	Implemented *bool                                 `json:"implemented"`
	Meaning     humanCoordinationConformanceNormative `json:"meaning"`
}

type humanCoordinationConformanceScope struct {
	Product            string   `json:"product"`
	ExcludedComponents []string `json:"excluded_components"`
}

type humanCoordinationProductionClaim struct {
	Available *bool                                 `json:"available"`
	Reason    humanCoordinationConformanceNormative `json:"reason"`
}

type humanCoordinationConformanceProfile struct {
	ID              string                                    `json:"id"`
	Maturity        string                                    `json:"maturity"`
	CapabilityBased *bool                                     `json:"capability_based"`
	DependsOn       []string                                  `json:"depends_on"`
	Requirements    []humanCoordinationConformanceRequirement `json:"requirements"`
}

type humanCoordinationConformanceRequirement struct {
	ID                 string                                `json:"id"`
	Normative          humanCoordinationConformanceNormative `json:"normative"`
	Status             string                                `json:"status"`
	Capability         string                                `json:"capability"`
	OptionalCapability *bool                                 `json:"optional_capability"`
	Tests              []humanCoordinationConformanceTestRef `json:"tests"`
	Evidence           []string                              `json:"evidence"`
}

type humanCoordinationConformanceNormative struct {
	EN string `json:"en"`
	JA string `json:"ja"`
}

type humanCoordinationConformanceTestRef struct {
	Format  string `json:"format"`
	Package string `json:"package"`
	Name    string `json:"name"`
}

type humanCoordinationOperationBoundary struct {
	ID                string                                `json:"id"`
	Classification    string                                `json:"classification"`
	Operations        []string                              `json:"operations"`
	ProfileID         string                                `json:"profile_id,omitempty"`
	AssuranceLevel    string                                `json:"assurance_level,omitempty"`
	TranscriptDomain  string                                `json:"transcript_domain,omitempty"`
	ActorSource       string                                `json:"actor_source"`
	ParticipantSource string                                `json:"participant_source"`
	RealmSource       string                                `json:"realm_source"`
	Freshness         string                                `json:"freshness"`
	Replay            string                                `json:"replay"`
	ErrorSurface      string                                `json:"error_surface"`
	StoreOrder        string                                `json:"store_order"`
	NetworkExposure   string                                `json:"network_exposure"`
	DebugEvidence     string                                `json:"debug_evidence"`
	Tests             []humanCoordinationConformanceTestRef `json:"tests"`
}

type humanCoordinationProfileExpectation struct {
	Family           string
	RequirementCount int
	Maturity         string
	CapabilityBased  bool
	Dependencies     []string
}

func TestHumanCoordinationConformanceManifestV1(t *testing.T) {
	t.Parallel()

	repositoryRoot := humanCoordinationRepositoryRoot(t)
	manifestPath := filepath.Join(repositoryRoot, "testdata", "human-coordination-conformance-v1.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read conformance manifest: %v", err)
	}

	var manifest humanCoordinationConformanceManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode conformance manifest: %v", err)
	}
	if err := humanCoordinationRequireJSONEOF(decoder); err != nil {
		t.Fatalf("decode conformance manifest: %v", err)
	}
	if manifest.Schema != humanCoordinationConformanceSchemaV1 {
		t.Fatalf("schema = %q, want %q", manifest.Schema, humanCoordinationConformanceSchemaV1)
	}
	if strings.TrimSpace(manifest.Scope.Product) == "" {
		t.Fatal("scope.product is empty")
	}
	humanCoordinationCheckExcludedComponents(t, manifest.Scope.ExcludedComponents)
	humanCoordinationCheckHumanAssurance(t, manifest.HumanAssurance)
	if manifest.ProductionClaim.Available == nil {
		t.Fatal("production_claim.available must be declared")
	}
	if *manifest.ProductionClaim.Available {
		t.Fatal("production conformance claim must remain unavailable")
	}
	if strings.TrimSpace(manifest.ProductionClaim.Reason.EN) == "" || strings.TrimSpace(manifest.ProductionClaim.Reason.JA) == "" {
		t.Fatal("production claim requires non-empty English and Japanese reasons")
	}

	expectations := map[string]humanCoordinationProfileExpectation{
		"asb.human-coordination.core/v1": {
			Family: "CORE", RequirementCount: 11, Maturity: "developer-preview",
			Dependencies: []string{},
		},
		"asb.human-coordination.task-action/v1": {
			Family: "TA", RequirementCount: 9, Maturity: "developer-preview",
			Dependencies: []string{"asb.human-coordination.core/v1"},
		},
		"asb.human-coordination.relay/v1": {
			Family: "RLY", RequirementCount: 8, Maturity: "developer-preview",
			Dependencies: []string{"asb.human-coordination.core/v1"},
		},
		"asb.human-coordination.http/v1": {
			Family: "HTTP", RequirementCount: 9, Maturity: "developer-preview",
			Dependencies: []string{"asb.human-coordination.core/v1"},
		},
		"asb.human-coordination.production/v1": {
			Family: "PROD", RequirementCount: 8, Maturity: "unavailable", CapabilityBased: true,
			Dependencies: []string{"asb.human-coordination.core/v1"},
		},
	}
	if len(manifest.Profiles) != len(expectations) {
		t.Fatalf("profile count = %d, want %d", len(manifest.Profiles), len(expectations))
	}

	profiles := make(map[string]humanCoordinationConformanceProfile, len(manifest.Profiles))
	for _, profile := range manifest.Profiles {
		expectation, known := expectations[profile.ID]
		if !known {
			t.Fatalf("unknown profile %q", profile.ID)
		}
		if _, duplicate := profiles[profile.ID]; duplicate {
			t.Fatalf("duplicate profile %q", profile.ID)
		}
		profiles[profile.ID] = profile
		if profile.Maturity != expectation.Maturity {
			t.Errorf("profile %s maturity = %q, want %q", profile.ID, profile.Maturity, expectation.Maturity)
		}
		if profile.CapabilityBased == nil {
			t.Errorf("profile %s capability_based must be declared", profile.ID)
		} else if *profile.CapabilityBased != expectation.CapabilityBased {
			t.Errorf("profile %s capability_based = %t, want %t", profile.ID, *profile.CapabilityBased, expectation.CapabilityBased)
		}
		if got := humanCoordinationSortedCopy(profile.DependsOn); !humanCoordinationStringsEqual(got, expectation.Dependencies) {
			t.Errorf("profile %s dependencies = %v, want %v", profile.ID, got, expectation.Dependencies)
		}
		if len(profile.Requirements) != expectation.RequirementCount {
			t.Errorf("profile %s requirement count = %d, want %d", profile.ID, len(profile.Requirements), expectation.RequirementCount)
		}
	}
	for profileID := range expectations {
		if _, present := profiles[profileID]; !present {
			t.Errorf("missing profile %q", profileID)
		}
	}
	humanCoordinationCheckDependencies(t, profiles)

	validStatuses := map[string]bool{
		"implemented": true, "reference-only": true, "unimplemented": true, "unqualified": true,
	}
	requirementPattern := regexp.MustCompile(`^ASB-HC-(CORE|TA|RLY|HTTP|PROD)-([0-9]{3})$`)
	testNamePattern := regexp.MustCompile(`^Test[A-Za-z0-9_]+$`)
	testPackagePattern := regexp.MustCompile(`^\./(?:pkg/[A-Za-z0-9_./-]+|schemas)$`)
	requirementIDs := make(map[string]bool)
	requirements := make(map[string]humanCoordinationConformanceRequirement)
	familyNumbers := make(map[string]map[int]bool)
	packageTests := make(map[string]map[string]bool)
	humanCoordinationCheckOperationBoundaries(
		t, repositoryRoot, manifest.OperationBoundaries,
		testPackagePattern, testNamePattern, packageTests,
	)

	for _, profile := range manifest.Profiles {
		expectation := expectations[profile.ID]
		for _, requirement := range profile.Requirements {
			match := requirementPattern.FindStringSubmatch(requirement.ID)
			if match == nil {
				t.Errorf("requirement ID %q does not use the ASB-HC family format", requirement.ID)
				continue
			}
			if match[1] != expectation.Family {
				t.Errorf("requirement %s belongs to %s, want family %s", requirement.ID, match[1], expectation.Family)
			}
			if requirementIDs[requirement.ID] {
				t.Errorf("duplicate requirement ID %s", requirement.ID)
			}
			requirementIDs[requirement.ID] = true
			requirements[requirement.ID] = requirement
			number, err := strconv.Atoi(match[2])
			if err != nil {
				t.Errorf("requirement %s number: %v", requirement.ID, err)
				continue
			}
			if familyNumbers[match[1]] == nil {
				familyNumbers[match[1]] = make(map[int]bool)
			}
			familyNumbers[match[1]][number] = true

			humanCoordinationCheckNormativeText(t, requirement)
			if !validStatuses[requirement.Status] {
				t.Errorf("requirement %s has unknown status %q", requirement.ID, requirement.Status)
			}
			if strings.TrimSpace(requirement.Capability) == "" {
				t.Errorf("requirement %s capability is empty", requirement.ID)
			}
			if requirement.OptionalCapability == nil {
				t.Errorf("requirement %s optional_capability must be declared", requirement.ID)
			}
			if requirement.Status == "implemented" || requirement.Status == "reference-only" {
				if len(requirement.Tests) == 0 {
					t.Errorf("%s status %s requires at least one exact test", requirement.ID, requirement.Status)
				}
				if len(requirement.Evidence) == 0 {
					t.Errorf("%s status %s requires at least one evidence path", requirement.ID, requirement.Status)
				}
			}
			for _, reference := range requirement.Tests {
				humanCoordinationCheckTestReference(t, repositoryRoot, requirement.ID, reference, testPackagePattern, testNamePattern, packageTests)
			}
			for _, evidence := range requirement.Evidence {
				humanCoordinationCheckEvidencePath(t, repositoryRoot, requirement.ID, evidence)
			}
		}
	}

	for _, expectation := range expectations {
		numbers := familyNumbers[expectation.Family]
		for number := 1; number <= expectation.RequirementCount; number++ {
			if !numbers[number] {
				t.Errorf("family %s is missing requirement %03d", expectation.Family, number)
			}
		}
		for number := range numbers {
			if number < 1 || number > expectation.RequirementCount {
				t.Errorf("family %s has out-of-range requirement %03d", expectation.Family, number)
			}
		}
	}

	humanCoordinationCheckFixedDecisions(t, requirements)
	humanCoordinationCheckProductionStatuses(t, requirements)
}

func humanCoordinationRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate conformance test source")
	}
	return filepath.Dir(filepath.Dir(source))
}

func humanCoordinationRequireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func humanCoordinationCheckExcludedComponents(t *testing.T, got []string) {
	t.Helper()
	want := []string{"integrations/cocos", "modules/attestation/snp", "modules/attestation/tdx"}
	if sorted := humanCoordinationSortedCopy(got); !humanCoordinationStringsEqual(sorted, want) {
		t.Errorf("excluded components = %v, want %v", sorted, want)
	}
}

func humanCoordinationCheckHumanAssurance(t *testing.T, assurance humanCoordinationHumanAssurance) {
	t.Helper()

	const (
		currentProfile = "asb.taskcoord-human-request/v1"
		currentLevel   = "gateway-asserted-for-human"
	)
	if assurance.CurrentProfile != currentProfile {
		t.Errorf("human assurance current_profile = %q, want %q", assurance.CurrentProfile, currentProfile)
	}
	if assurance.CurrentLevel != currentLevel {
		t.Errorf("human assurance current_level = %q, want %q", assurance.CurrentLevel, currentLevel)
	}
	wantLevels := map[string]bool{
		"gateway-asserted-for-human":   true,
		"authenticated-human-evidence": false,
		"human-held-key-exact-request": false,
	}
	if len(assurance.Levels) != len(wantLevels) {
		t.Fatalf("human assurance level count = %d, want %d", len(assurance.Levels), len(wantLevels))
	}
	seen := make(map[string]bool, len(assurance.Levels))
	for _, level := range assurance.Levels {
		wantImplemented, known := wantLevels[level.ID]
		if !known {
			t.Errorf("unknown Human assurance level %q", level.ID)
			continue
		}
		if seen[level.ID] {
			t.Errorf("duplicate Human assurance level %q", level.ID)
		}
		seen[level.ID] = true
		if level.Implemented == nil {
			t.Errorf("Human assurance level %s must declare implemented", level.ID)
		} else if *level.Implemented != wantImplemented {
			t.Errorf("Human assurance level %s implemented = %t, want %t", level.ID, *level.Implemented, wantImplemented)
		}
		if strings.TrimSpace(level.Meaning.EN) == "" || strings.TrimSpace(level.Meaning.JA) == "" {
			t.Errorf("Human assurance level %s needs English and Japanese meanings", level.ID)
		}
	}
	wantNonGuarantees := []string{
		"authenticated-human-evidence",
		"human-held-key",
		"human-liveness",
		"legal-consent",
		"ui-confirmation",
	}
	if got := humanCoordinationSortedCopy(assurance.NonGuarantees); !humanCoordinationStringsEqual(got, wantNonGuarantees) {
		t.Errorf("Human assurance non_guarantees = %v, want %v", got, wantNonGuarantees)
	}
}

func humanCoordinationCheckOperationBoundaries(
	t *testing.T,
	repositoryRoot string,
	boundaries []humanCoordinationOperationBoundary,
	packagePattern *regexp.Regexp,
	testNamePattern *regexp.Regexp,
	packageTests map[string]map[string]bool,
) {
	t.Helper()
	type expectation struct {
		classification  string
		profileID       string
		assuranceLevel  string
		transcript      string
		networkExposure string
		debugEvidence   string
	}
	expectations := map[string]expectation{
		"human-taskcoord": {
			classification: "external-asb", profileID: "asb.taskcoord-human-request/v1",
			assuranceLevel:  "gateway-asserted-for-human",
			transcript:      "ASB-TASKCOORD-HUMAN-REQUEST-v1",
			networkExposure: "human-ingress-and-programmatic-profile", debugEvidence: "signed-simulated-asb",
		},
		"agent-relay-authorization": {
			classification: "external-asb", profileID: "asb.taskcoord-agent-relay/v1",
			transcript:      "ASB-HUMAN-RELAY-INTENT-v1",
			networkExposure: "programmatic-profile", debugEvidence: "signed-simulated-asb",
		},
		"agent-taskcoord": {
			classification: "trusted-internal", networkExposure: "none", debugEvidence: "fixture-projection",
		},
		"action-acceptance": {
			classification: "trusted-internal", transcript: "asb.action-accept-request/v1",
			networkExposure: "none", debugEvidence: "fixture-projection",
		},
		"action-mutation": {
			classification: "trusted-internal", transcript: "asb.action-mutation-request/v1",
			networkExposure: "none", debugEvidence: "fixture-projection",
		},
		"human-matching": {
			classification: "trusted-internal", networkExposure: "none", debugEvidence: "fixture-projection",
		},
		"reachability-administration": {
			classification: "trusted-internal", networkExposure: "none", debugEvidence: "fixture-projection",
		},
		"relay-queue": {
			classification: "trusted-internal", networkExposure: "none", debugEvidence: "asb-derived-projection",
		},
		"relay-dispatch": {
			classification: "trusted-internal", networkExposure: "none", debugEvidence: "trusted-worker",
		},
	}
	if len(boundaries) != len(expectations) {
		t.Fatalf("operation boundary count = %d, want %d", len(boundaries), len(expectations))
	}

	seen := make(map[string]bool, len(boundaries))
	for _, boundary := range boundaries {
		want, known := expectations[boundary.ID]
		if !known {
			t.Errorf("unknown operation boundary %q", boundary.ID)
			continue
		}
		if seen[boundary.ID] {
			t.Errorf("duplicate operation boundary %q", boundary.ID)
			continue
		}
		seen[boundary.ID] = true
		if boundary.Classification != want.classification {
			t.Errorf("boundary %s classification = %q, want %q", boundary.ID, boundary.Classification, want.classification)
		}
		if boundary.ProfileID != want.profileID {
			t.Errorf("boundary %s profile_id = %q, want %q", boundary.ID, boundary.ProfileID, want.profileID)
		}
		if boundary.AssuranceLevel != want.assuranceLevel {
			t.Errorf("boundary %s assurance_level = %q, want %q", boundary.ID, boundary.AssuranceLevel, want.assuranceLevel)
		}
		if boundary.TranscriptDomain != want.transcript {
			t.Errorf("boundary %s transcript_domain = %q, want %q", boundary.ID, boundary.TranscriptDomain, want.transcript)
		}
		if boundary.NetworkExposure != want.networkExposure {
			t.Errorf("boundary %s network_exposure = %q, want %q", boundary.ID, boundary.NetworkExposure, want.networkExposure)
		}
		if boundary.DebugEvidence != want.debugEvidence {
			t.Errorf("boundary %s debug_evidence = %q, want %q", boundary.ID, boundary.DebugEvidence, want.debugEvidence)
		}
		if len(boundary.Operations) == 0 {
			t.Errorf("boundary %s has no operations", boundary.ID)
		}
		operations := make(map[string]bool, len(boundary.Operations))
		for _, operation := range boundary.Operations {
			if strings.TrimSpace(operation) == "" {
				t.Errorf("boundary %s has an empty operation", boundary.ID)
			}
			if operations[operation] {
				t.Errorf("boundary %s repeats operation %q", boundary.ID, operation)
			}
			operations[operation] = true
		}
		for field, value := range map[string]string{
			"actor_source":       boundary.ActorSource,
			"participant_source": boundary.ParticipantSource,
			"realm_source":       boundary.RealmSource,
			"freshness":          boundary.Freshness,
			"replay":             boundary.Replay,
			"error_surface":      boundary.ErrorSurface,
			"store_order":        boundary.StoreOrder,
		} {
			if strings.TrimSpace(value) == "" {
				t.Errorf("boundary %s %s is empty", boundary.ID, field)
			}
		}
		if boundary.Classification == "external-asb" && len(boundary.Tests) < 2 {
			t.Errorf("external boundary %s needs positive and negative tests", boundary.ID)
		}
		if boundary.Classification == "trusted-internal" && boundary.ProfileID != "" {
			t.Errorf("internal boundary %s must not claim an external profile", boundary.ID)
		}
		for _, reference := range boundary.Tests {
			humanCoordinationCheckTestReference(
				t, repositoryRoot, "operation boundary "+boundary.ID, reference,
				packagePattern, testNamePattern, packageTests,
			)
		}
	}
	for id := range expectations {
		if !seen[id] {
			t.Errorf("missing operation boundary %q", id)
		}
	}
}

func humanCoordinationCheckDependencies(t *testing.T, profiles map[string]humanCoordinationConformanceProfile) {
	t.Helper()
	for id, profile := range profiles {
		seen := make(map[string]bool)
		for _, dependency := range profile.DependsOn {
			if dependency == id {
				t.Errorf("profile %s depends on itself", id)
			}
			if _, known := profiles[dependency]; !known {
				t.Errorf("profile %s has unknown dependency %s", id, dependency)
			}
			if seen[dependency] {
				t.Errorf("profile %s repeats dependency %s", id, dependency)
			}
			seen[dependency] = true
		}
	}

	const (
		unseen = iota
		visiting
		done
	)
	state := make(map[string]int)
	var visit func(string)
	visit = func(id string) {
		if state[id] == visiting {
			t.Errorf("profile dependency cycle reaches %s", id)
			return
		}
		if state[id] == done {
			return
		}
		state[id] = visiting
		for _, dependency := range profiles[id].DependsOn {
			if _, known := profiles[dependency]; known {
				visit(dependency)
			}
		}
		state[id] = done
	}
	for id := range profiles {
		visit(id)
	}
}

func humanCoordinationCheckNormativeText(t *testing.T, requirement humanCoordinationConformanceRequirement) {
	t.Helper()
	if strings.TrimSpace(requirement.Normative.EN) == "" || strings.TrimSpace(requirement.Normative.JA) == "" {
		t.Errorf("requirement %s needs non-empty English and Japanese text", requirement.ID)
		return
	}
	if !strings.Contains(requirement.Normative.EN, "MUST") && !strings.Contains(requirement.Normative.EN, "MAY") {
		t.Errorf("requirement %s English text has no normative MUST or MAY", requirement.ID)
	}
}

func humanCoordinationCheckTestReference(
	t *testing.T,
	repositoryRoot string,
	requirementID string,
	reference humanCoordinationConformanceTestRef,
	packagePattern *regexp.Regexp,
	testNamePattern *regexp.Regexp,
	packageTests map[string]map[string]bool,
) {
	t.Helper()
	if reference.Format != "go-test" {
		t.Errorf("requirement %s has unknown test format %q", requirementID, reference.Format)
		return
	}
	if !packagePattern.MatchString(reference.Package) {
		t.Errorf("requirement %s has invalid test package %q", requirementID, reference.Package)
		return
	}
	if !testNamePattern.MatchString(reference.Name) {
		t.Errorf("requirement %s has invalid test name %q", requirementID, reference.Name)
		return
	}
	if packageTests[reference.Package] == nil {
		packageTests[reference.Package] = humanCoordinationReadPackageTests(t, repositoryRoot, reference.Package)
	}
	if !packageTests[reference.Package][reference.Name] {
		t.Errorf("requirement %s references missing exact test %s %s", requirementID, reference.Package, reference.Name)
	}
}

func humanCoordinationReadPackageTests(t *testing.T, repositoryRoot, packagePath string) map[string]bool {
	t.Helper()
	directory := filepath.Join(repositoryRoot, filepath.FromSlash(strings.TrimPrefix(packagePath, "./")))
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Errorf("read test package %s: %v", packagePath, err)
		return map[string]bool{}
	}
	tests := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			continue
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && strings.HasPrefix(function.Name.Name, "Test") {
				tests[function.Name.Name] = true
			}
		}
	}
	return tests
}

func humanCoordinationCheckEvidencePath(t *testing.T, repositoryRoot, requirementID, evidence string) {
	t.Helper()
	if evidence == "" || filepath.IsAbs(evidence) || filepath.Clean(evidence) != evidence || evidence == "." || strings.HasPrefix(evidence, ".."+string(filepath.Separator)) {
		t.Errorf("requirement %s has invalid evidence path %q", requirementID, evidence)
		return
	}
	info, err := os.Stat(filepath.Join(repositoryRoot, filepath.FromSlash(evidence)))
	if err != nil {
		t.Errorf("requirement %s evidence %q: %v", requirementID, evidence, err)
		return
	}
	if !info.Mode().IsRegular() {
		t.Errorf("requirement %s evidence %q is not a regular file", requirementID, evidence)
	}
}

func humanCoordinationCheckFixedDecisions(t *testing.T, requirements map[string]humanCoordinationConformanceRequirement) {
	t.Helper()
	wants := map[string][]string{
		"ASB-HC-CORE-004": {"descriptive responsibility labels", "MUST NOT grant permission", "enclosing verifier"},
		"ASB-HC-CORE-007": {"terminal state", "MUST NOT mutate the Assignment"},
		"ASB-HC-CORE-010": {"verifier-local", "within that realm", "caller-controlled realm field"},
		"ASB-HC-CORE-011": {"MUST NOT appear in public Agent discovery", "optional consent-scoped capability", "opaque"},
		"ASB-HC-TA-001":   {"zero or one", "second binding"},
		"ASB-HC-TA-009":   {"business identity", "exact proof-attempt identity", "MUST NOT create state", "MUST require reconciliation"},
		"ASB-HC-RLY-002":  {"contact routing and metadata", "MUST NOT be treated as Human approval of the exact content"},
		"ASB-HC-PROD-001": {"MUST name each selected", "MUST NOT imply Task-Action or relay"},
	}
	for id, fragments := range wants {
		requirement, present := requirements[id]
		if !present {
			t.Errorf("missing fixed-decision requirement %s", id)
			continue
		}
		for _, fragment := range fragments {
			if !strings.Contains(requirement.Normative.EN, fragment) {
				t.Errorf("requirement %s must contain fixed decision %q", id, fragment)
			}
		}
	}
}

func humanCoordinationCheckProductionStatuses(t *testing.T, requirements map[string]humanCoordinationConformanceRequirement) {
	t.Helper()
	wants := map[string]string{
		"ASB-HC-PROD-001": "reference-only",
		"ASB-HC-PROD-002": "reference-only",
		"ASB-HC-PROD-003": "reference-only",
		"ASB-HC-PROD-004": "reference-only",
		"ASB-HC-PROD-005": "reference-only",
		"ASB-HC-PROD-006": "unqualified",
		"ASB-HC-PROD-007": "unqualified",
		"ASB-HC-PROD-008": "unimplemented",
	}
	for id, want := range wants {
		if got := requirements[id].Status; got != want {
			t.Errorf("requirement %s status = %q, want %q", id, got, want)
		}
	}
}

func humanCoordinationSortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func humanCoordinationStringsEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
