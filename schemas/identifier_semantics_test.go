// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestHumanCoordinationIdentifierSchemasShareStructuralRules(t *testing.T) {
	t.Parallel()

	taskParticipant, err := os.ReadFile(taskParticipantSchemaFile)
	if err != nil {
		t.Fatal(err)
	}
	definitions := []struct {
		name       string
		url        string
		raw        []byte
		definition string
	}{
		{"TaskCoord", "https://github.com/ToppyMicroServices/agents-secure-binding/schemas/task-participant-v1.schema.json", taskParticipant, "identifier"},
		{"Human ingress", humanIngressSchemaURL, humanIngressSchema, "identifier"},
		{"Human relay", humanRelaySchemaURL, humanRelaySchemaBytes, "identifier"},
		{"Action lifecycle", actionLifecycleSchemaURL, actionLifecycleSchemaBytes, "id"},
		{"Task Action binding", taskActionBindingSchemaURL, taskActionBindingSchemaBytes, "id"},
	}

	asciiLimit := strings.Repeat("a", 256)
	multibyteLimit := strings.Repeat("é", 128)
	semanticOnlyOverflow := strings.Repeat("é", 129)
	if len(multibyteLimit) != 256 || utf8.RuneCountInString(multibyteLimit) != 128 {
		t.Fatal("multibyte boundary fixture is invalid")
	}
	if len(semanticOnlyOverflow) != 258 || utf8.RuneCountInString(semanticOnlyOverflow) != 129 {
		t.Fatal("semantic-only overflow fixture is invalid")
	}

	valid := []string{
		"identifier",
		asciiLimit,
		multibyteLimit,
		"tenant:É",
		"tenant:E\u0301",
		"case:SENSITIVE",
		"interior whitespace",
		semanticOnlyOverflow,
	}
	invalid := []string{
		"",
		strings.Repeat("a", 257),
		" 000000000", // deterministic fuzz seed f093178037932967
		"identifier ",
		"\u00a0identifier",
		"identifier\u3000",
		"identifier\u0001control",
		"identifier\u0085control",
	}

	for _, definition := range definitions {
		definition := definition
		t.Run(definition.name, func(t *testing.T) {
			t.Parallel()
			schema := compileDefinition(t, definition.url, definition.raw, definition.definition)
			for _, value := range valid {
				if err := schema.Validate(value); err != nil {
					t.Errorf("structurally valid identifier %q rejected: %v", value, err)
				}
			}
			for _, value := range invalid {
				if err := schema.Validate(value); err == nil {
					t.Errorf("structurally invalid identifier %q accepted", value)
				}
			}
		})
	}
}

func TestActionIdentifierSchemaPreservesMarkupCharacterRestriction(t *testing.T) {
	t.Parallel()
	schema := compileDefinition(t, actionLifecycleSchemaURL, actionLifecycleSchemaBytes, "id")
	for _, value := range []string{"action:<one>", "action&one", `action"one`, "action'one"} {
		if err := schema.Validate(value); err == nil {
			t.Errorf("Action identifier with markup-sensitive character accepted: %q", value)
		}
	}
}

func TestHumanCoordinationIdentifierInventoryCoversGoStructs(t *testing.T) {
	t.Parallel()

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate identifier inventory test")
	}
	repositoryRoot := filepath.Dir(filepath.Dir(sourceFile))
	document, err := os.ReadFile(filepath.Join(repositoryRoot, "docs", "human-coordination-field-semantics-v1.md"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(document), "\n")

	targets := []struct {
		path             string
		label            string
		unexportedStruct map[string]bool
	}{
		{path: "pkg/taskcoord", label: "taskcoord"},
		{path: "pkg/taskcoord/asbbinding", label: "taskcoord/asbbinding"},
		{path: "pkg/taskcoord/actionbinding", label: "taskcoord/actionbinding"},
		{path: "pkg/actionlifecycle", label: "actionlifecycle"},
		{path: "pkg/humanrelay", label: "humanrelay"},
		{path: "pkg/humanrelay/asbbinding", label: "humanrelay/asbbinding"},
		{
			path:  "pkg/production",
			label: "production",
			unexportedStruct: map[string]bool{
				"redisTaskEvent":      true,
				"redisOutboxDelivery": true,
			},
		},
	}

	var missing []string
	for _, target := range targets {
		directory := filepath.Join(repositoryRoot, filepath.FromSlash(target.path))
		packages, err := parser.ParseDir(token.NewFileSet(), directory, func(info os.FileInfo) bool {
			return !strings.HasSuffix(info.Name(), "_test.go")
		}, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", target.path, err)
		}
		for _, parsedPackage := range packages {
			for _, file := range parsedPackage.Files {
				for _, declaration := range file.Decls {
					general, ok := declaration.(*ast.GenDecl)
					if !ok || general.Tok != token.TYPE {
						continue
					}
					for _, specification := range general.Specs {
						typeSpecification, ok := specification.(*ast.TypeSpec)
						if !ok {
							continue
						}
						included := ast.IsExported(typeSpecification.Name.Name)
						if target.unexportedStruct != nil {
							included = target.unexportedStruct[typeSpecification.Name.Name]
						}
						if !included {
							continue
						}
						structure, ok := typeSpecification.Type.(*ast.StructType)
						if !ok {
							continue
						}
						for _, field := range structure.Fields.List {
							if !identifierInventoryStringType(field.Type) {
								continue
							}
							for _, fieldName := range field.Names {
								if !ast.IsExported(fieldName.Name) || !identifierInventoryField(fieldName.Name) {
									continue
								}
								typeName := target.label + "." + typeSpecification.Name.Name
								if !identifierInventoryContains(lines, typeName, fieldName.Name) {
									missing = append(missing, typeName+"."+fieldName.Name)
								}
							}
						}
					}
				}
			}
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		t.Fatalf("Human Coordination identifier fields missing from documentation inventory: %s", strings.Join(missing, ", "))
	}
}

func identifierInventoryStringType(expression ast.Expr) bool {
	switch candidate := expression.(type) {
	case *ast.Ident:
		return candidate.Name == "string"
	case *ast.ArrayType:
		identifier, ok := candidate.Elt.(*ast.Ident)
		return candidate.Len == nil && ok && identifier.Name == "string"
	default:
		return false
	}
}

func identifierInventoryField(name string) bool {
	if name == "ID" || strings.HasSuffix(name, "ID") || strings.HasSuffix(name, "IDs") {
		return true
	}
	switch name {
	case "VerifierNonce", "InReplyTo", "Supersedes", "Purpose", "Capability",
		"Signal", "ErrorCode", "AckRef", "ProviderAckRef":
		return true
	default:
		return false
	}
}

func identifierInventoryContains(lines []string, typeName, fieldName string) bool {
	typeMarker := "`" + typeName + "`"
	fieldMarker := "`" + fieldName + "`"
	for _, line := range lines {
		if strings.HasPrefix(line, "| ") && strings.Count(line, "|") >= 4 &&
			strings.Contains(line, typeMarker) && strings.Contains(line, fieldMarker) {
			return true
		}
	}
	return false
}

func compileDefinition(t *testing.T, url string, raw []byte, definition string) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource(url, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(url + "#/$defs/" + definition)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}
