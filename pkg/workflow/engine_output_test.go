//go:build !integration

package workflow

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEngineArtifactPaths_ClaudeDebugLog(t *testing.T) {
	paths := getEngineArtifactPaths(NewClaudeEngine())

	assert.Contains(t, paths, claudeDebugLogFile)
	assert.Contains(t, paths, RedactedURLsLogPath)
}

// TestGetEngineArtifactPaths_WithOutputFiles verifies that engines with declared output files
// return those paths plus the redacted URLs log appended.
func TestGetEngineArtifactPaths_WithOutputFiles(t *testing.T) {
	// Codex engine declares output files
	codexEngine := NewCodexEngine()
	declaredFiles := codexEngine.GetDeclaredOutputFiles()
	require.NotEmpty(t, declaredFiles, "Codex engine must declare at least one output file for this test")

	paths := getEngineArtifactPaths(codexEngine)

	assert.NotNil(t, paths, "getEngineArtifactPaths should return paths when engine has output files")
	assert.Len(t, paths, len(declaredFiles)+1, "result should contain declared files plus the redacted URLs log")

	// The redacted URLs log should be the last appended path
	assert.Equal(t, RedactedURLsLogPath, paths[len(paths)-1],
		"RedactedURLsLogPath should be the last entry in the returned paths")

	// All original declared files should be present
	for _, f := range declaredFiles {
		assert.Contains(t, paths, f, "declared file %q should appear in the result", f)
	}
}

// TestGetEngineArtifactPaths_GeminiEngine verifies Gemini wildcard paths are preserved.
func TestGetEngineArtifactPaths_GeminiEngine(t *testing.T) {
	geminiEngine := NewGeminiEngine()
	paths := getEngineArtifactPaths(geminiEngine)

	require.NotNil(t, paths, "Gemini engine should have artifact paths")

	// Gemini declares the client-error wildcard log
	wildcardFound := false
	for _, p := range paths {
		if strings.Contains(p, "gemini-client-error") {
			wildcardFound = true
			break
		}
	}
	assert.True(t, wildcardFound, "Gemini artifact paths should include gemini-client-error wildcard")

	// Redacted URLs log should be present
	assert.Contains(t, paths, RedactedURLsLogPath, "RedactedURLsLogPath should be present in Gemini artifact paths")
}

// TestGenerateEngineOutputCleanup_NoOutputFiles verifies that engines with no declared
// output files produce no cleanup YAML.
func TestGenerateEngineOutputCleanup_NoOutputFiles(t *testing.T) {
	compiler := NewCompiler()
	var yaml strings.Builder

	// Claude has no declared output files
	claudeEngine := NewClaudeEngine()
	compiler.generateEngineOutputCleanup(&yaml, claudeEngine)

	assert.Empty(t, yaml.String(), "generateEngineOutputCleanup should produce no output for engines with no declared files")
}

// TestGenerateEngineOutputCleanup_WithWorkspaceFiles verifies that workspace files
// (outside /tmp/gh-aw/) get a cleanup step while /tmp/gh-aw/ files do not.
func TestGenerateEngineOutputCleanup_WithWorkspaceFiles(t *testing.T) {
	compiler := NewCompiler()
	var yaml strings.Builder

	// Codex declares /tmp/gh-aw/ files; those shouldn't get a rm -fr cleanup
	codexEngine := NewCodexEngine()
	declaredFiles := codexEngine.GetDeclaredOutputFiles()
	require.NotEmpty(t, declaredFiles, "Codex must declare files for this test")

	compiler.generateEngineOutputCleanup(&yaml, codexEngine)
	result := yaml.String()

	// If all Codex output files are under /tmp/gh-aw/, no cleanup step should be emitted
	allUnderTmpGhAw := true
	for _, f := range declaredFiles {
		if !strings.HasPrefix(f, "/tmp/gh-aw/") {
			allUnderTmpGhAw = false
			break
		}
	}

	if allUnderTmpGhAw {
		assert.Empty(t, result, "no cleanup step should be emitted when all files are under /tmp/gh-aw/")
	} else {
		assert.Contains(t, result, "Clean up engine output files", "cleanup step should be present for workspace files")
	}
}

func TestBuildAgentOutputFilesSetup(t *testing.T) {
	tests := []struct {
		name            string
		stepSummaryPath string
		logFiles        []string
		expected        string
	}{
		{
			name:            "step summary and log file",
			stepSummaryPath: AgentStepSummaryPath,
			logFiles:        []string{"/tmp/gh-aw/agent-stdio.log"},
			expected: "touch /tmp/gh-aw/agent-step-summary.md\n" +
				"(umask 177 && touch /tmp/gh-aw/agent-stdio.log)",
		},
		{
			name:            "extra log files share one private touch",
			stepSummaryPath: AgentStepSummaryPath,
			logFiles:        []string{"/tmp/gh-aw/agent-stdio.log", claudeDebugLogFile},
			expected: "touch /tmp/gh-aw/agent-step-summary.md\n" +
				"(umask 177 && touch /tmp/gh-aw/agent-stdio.log /tmp/gh-aw/claude-debug.log)",
		},
		{
			name:     "no step summary",
			logFiles: []string{"/tmp/gh-aw/threat-detection/detection.log"},
			expected: "(umask 177 && touch /tmp/gh-aw/threat-detection/detection.log)",
		},
		{
			name:            "no log files",
			stepSummaryPath: AgentStepSummaryPath,
			expected:        "touch /tmp/gh-aw/agent-step-summary.md",
		},
		{
			name:     "nothing to create",
			expected: "",
		},
		{
			name:            "paths are shell-escaped",
			stepSummaryPath: "/tmp/my summary.md",
			logFiles:        []string{"/tmp/it's.log"},
			expected: "touch '/tmp/my summary.md'\n" +
				`(umask 177 && touch '/tmp/it'\''s.log')`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildAgentOutputFilesSetup(tt.stepSummaryPath, tt.logFiles...))
		})
	}
}

// TestAgentExecutionStepCreatesOutputFiles verifies that every engine creates the
// files its execution step writes before the engine starts, with and without AWF.
func TestAgentExecutionStepCreatesOutputFiles(t *testing.T) {
	const logFile = "/tmp/gh-aw/agent-stdio.log"
	engines := []struct {
		engine   CodingAgentEngine
		expected string
	}{
		{NewClaudeEngine(), buildAgentOutputFilesSetup(AgentStepSummaryPath, logFile, claudeDebugLogFile)},
		{NewCodexEngine(), buildAgentOutputFilesSetup(AgentStepSummaryPath, logFile)},
		{NewCopilotEngine(), buildAgentOutputFilesSetup(AgentStepSummaryPath, logFile)},
		{NewGeminiEngine(), buildAgentOutputFilesSetup(AgentStepSummaryPath, logFile)},
		{NewPiEngine(), buildAgentOutputFilesSetup(AgentStepSummaryPath, logFile)},
	}

	for _, tt := range engines {
		for _, firewall := range []bool{true, false} {
			name := tt.engine.GetID() + "/firewall=" + strconv.FormatBool(firewall)
			t.Run(name, func(t *testing.T) {
				workflowData := &WorkflowData{
					Name:         "test-workflow",
					EngineConfig: &EngineConfig{ID: tt.engine.GetID()},
					NetworkPermissions: &NetworkPermissions{
						Firewall: &FirewallConfig{Enabled: firewall},
					},
				}
				steps := tt.engine.GetExecutionSteps(workflowData, logFile)
				require.NotEmpty(t, steps, "expected execution steps")
				// Step lines are YAML-indented; strip the indentation to compare scripts.
				var sb strings.Builder
				for _, step := range steps {
					for _, line := range step {
						sb.WriteString(strings.TrimSpace(line))
						sb.WriteByte('\n')
					}
				}
				script := sb.String()
				setupIdx := strings.Index(script, tt.expected+"\n")
				require.GreaterOrEqual(t, setupIdx, 0, "output files setup missing from steps:\n%s", script)
				// The engine invocation is the last reference to the log file (tee or AWF wrapper).
				require.Greater(t, strings.LastIndex(script, logFile), setupIdx+len(tt.expected),
					"output files must be created before the engine runs")
				assert.Equal(t, 1, strings.Count(script, "umask 177"), "log files should be created in one place")
			})
		}
	}
}
