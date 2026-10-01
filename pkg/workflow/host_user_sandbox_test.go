//go:build !integration

package workflow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostUserWorkflowData returns a minimal workflow that the host-user runtime accepts.
func hostUserWorkflowData() *WorkflowData {
	return &WorkflowData{
		Tools:         map[string]any{"github": map[string]any{"mode": "remote"}},
		EngineConfig:  &EngineConfig{ID: "claude"},
		RunsOn:        "runs-on: ubuntu-26.04",
		SandboxConfig: &SandboxConfig{Agent: &AgentSandboxConfig{Runtime: AgentRuntimeHostUser}},
	}
}

func TestValidateHostUserRuntime(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*WorkflowData)
		wantErr string
	}{
		{name: "ubuntu-26.04 claude workflow is accepted"},
		{name: "self-hosted runner is accepted", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: [self-hosted, linux]" }},
		{name: "services are allowed", mutate: func(d *WorkflowData) {
			d.ServicePortExpressions = `PORT: ${{ job.services.db.ports['5432'] }}`
		}},
		{name: "default runner is refused", mutate: func(d *WorkflowData) { d.RunsOn = "" }, wantErr: "explicit runs-on"},
		{name: "ubuntu-latest is refused", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: ubuntu-latest" }, wantErr: "does not work on ubuntu-latest"},
		{name: "ubuntu-24.04 is refused", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: ubuntu-24.04" }, wantErr: "does not work on ubuntu-24.04"},
		{name: "ubuntu-24.04-arm is refused", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: ubuntu-24.04-arm" }, wantErr: "does not work on ubuntu-24.04-arm"},
		{name: "macos is refused", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: macos-15" }, wantErr: "does not work on macos-15"},
		{name: "windows is refused", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: windows-latest" }, wantErr: "does not work on windows-latest"},
		{name: "default engine is refused", mutate: func(d *WorkflowData) { d.EngineConfig = nil }, wantErr: "only engine: claude"},
		{name: "codex is refused", mutate: func(d *WorkflowData) { d.EngineConfig.ID = "codex" }, wantErr: "only engine: claude"},
		{name: "non-anthropic provider is refused", mutate: func(d *WorkflowData) { d.EngineConfig.LLMProvider = LLMProviderOpenAI }, wantErr: "only the anthropic inference provider"},
		{name: "api-target is refused", mutate: func(d *WorkflowData) { d.EngineConfig.APITarget = "api.example.com" }, wantErr: "engine.api-target"},
		{name: "enclaves are refused", mutate: func(d *WorkflowData) { d.Enclaves = EnclavesConfig{{}} }, wantErr: "enclaves"},
		{name: "agent command is refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.Command = "awf" }, wantErr: "sandbox.agent.command"},
		{name: "agent args are refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.Args = []string{"--x"} }, wantErr: "sandbox.agent.args"},
		{name: "agent env is refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.Env = map[string]string{"A": "b"} }, wantErr: "sandbox.agent.env"},
		{name: "agent mounts are refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.Mounts = []string{"/a:/a:ro"} }, wantErr: "sandbox.agent.mounts"},
		{name: "agent memory is refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.Memory = "4g" }, wantErr: "sandbox.agent.memory"},
		{name: "agent images are refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.Images = map[string]string{"squid": "x"} }, wantErr: "sandbox.agent.images"},
		{name: "allow-host-ports is refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.AllowHostPorts = []int{9000} }, wantErr: "sandbox.agent.allow-host-ports"},
		{name: "ca-cert is refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.CACert = "/ca.pem" }, wantErr: "sandbox.agent.ca-cert"},
		{name: "config is refused", mutate: func(d *WorkflowData) { d.SandboxConfig.Agent.Config = &SandboxRuntimeConfig{} }, wantErr: "sandbox.agent.config"},
		{name: "targets are refused", mutate: func(d *WorkflowData) {
			d.SandboxConfig.Agent.Targets = map[string]*AgentAPIProxyTargetConfig{"anthropic": {}}
		}, wantErr: "sandbox.agent.targets"},
		{name: "token-steering is refused", mutate: func(d *WorkflowData) { v := true; d.SandboxConfig.Agent.TokenSteering = &v }, wantErr: "sandbox.agent.token-steering"},
		{name: "ubuntu-22.04 is refused", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: ubuntu-22.04" }, wantErr: "does not work on ubuntu-22.04"},
		{name: "ubuntu-slim is refused", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: ubuntu-slim" }, wantErr: "does not work on ubuntu-slim"},
		{name: "a refused label in a list is found", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: [self-hosted, ubuntu-24.04]" }, wantErr: "does not work on ubuntu-24.04"},
		{name: "a self-hosted label that only starts like a hosted one is accepted", mutate: func(d *WorkflowData) { d.RunsOn = "runs-on: ubuntu-latest-gpu" }},
		{name: "gh-proxy is refused", mutate: func(d *WorkflowData) { d.Tools["github"] = map[string]any{"mode": "gh-proxy"} }, wantErr: "gh-proxy"},
		{name: "arc-dind is refused", mutate: func(d *WorkflowData) { d.RunnerConfig = &RunnerConfig{Topology: RunnerTopologyArcDind} }, wantErr: "arc-dind"},
		{name: "cache-memory is refused", mutate: func(d *WorkflowData) { d.CacheMemoryConfig = &CacheMemoryConfig{Caches: []CacheMemoryEntry{{}}} }, wantErr: "cache-memory"},
		{name: "repo-memory is refused", mutate: func(d *WorkflowData) { d.RepoMemoryConfig = &RepoMemoryConfig{Memories: []RepoMemoryEntry{{}}} }, wantErr: "repo-memory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := hostUserWorkflowData()
			if tt.mutate != nil {
				tt.mutate(data)
			}
			err := validateSandboxConfig(data)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestHostUserRuntimeIsNotAWF(t *testing.T) {
	data := hostUserWorkflowData()
	assert.True(t, isHostUserRuntime(data))
	assert.False(t, isFirewallEnabled(data), "host-user must not wrap the agent in AWF")

	data.SandboxConfig.Agent.Disabled = true
	assert.False(t, isHostUserRuntime(data), "sandbox.agent: false is not host-user")
}

func TestApplyHostUserAgentEnv(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantEnv map[string]string
	}{
		{
			name: "API key moves to the proxy and the engine gets a placeholder",
			env: map[string]string{
				"ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}",
				"GH_AW_PROMPT":      "/tmp/gh-aw/aw-prompts/prompt.txt",
			},
			wantEnv: map[string]string{
				"ANTHROPIC_BASE_URL":   "http://127.0.0.1:10001",
				"ANTHROPIC_AUTH_TOKEN": hostUserPlaceholderAnthropicToken,
				"GH_AW_PROMPT":         "/tmp/gh-aw/aw-prompts/prompt.txt",
			},
		},
		{
			name: "secrets in any expression form are dropped",
			env: map[string]string{
				"INDEXED":   "${{ secrets['MY_TOKEN'] }}",
				"ALL":       "${{ toJSON(secrets) }}",
				"TOKEN":     "${{ github.token }}",
				"BAD-NAME":  "x",
				"LITERAL":   "my secrets are safe",
				"FROM_VARS": "${{ vars.SOMETHING }}",
			},
			wantEnv: map[string]string{
				"ANTHROPIC_BASE_URL":   "http://127.0.0.1:10001",
				"ANTHROPIC_AUTH_TOKEN": hostUserPlaceholderAnthropicToken,
				"LITERAL":              "my secrets are safe",
				"FROM_VARS":            "${{ vars.SOMETHING }}",
			},
		},
		{
			name: "every secret-bearing variable is dropped",
			env: map[string]string{
				"GH_TOKEN":       "${{ secrets.GH_AW_GITHUB_TOKEN || github.token }}",
				"MY_TOOL_SECRET": "${{ secrets.MY_TOOL_SECRET }}",
				"RUNNER_TEMP":    "${{ runner.temp }}",
			},
			wantEnv: map[string]string{
				"ANTHROPIC_BASE_URL":   "http://127.0.0.1:10001",
				"ANTHROPIC_AUTH_TOKEN": hostUserPlaceholderAnthropicToken,
				"RUNNER_TEMP":          "${{ runner.temp }}",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyHostUserAgentEnv(tt.env, LLMProviderAnthropic)
			assert.Equal(t, tt.wantEnv, tt.env)
		})
	}
}

// compileHostUserWorkflow compiles a host-user workflow with the given extra
// frontmatter and returns the lock file.
func compileHostUserWorkflow(t *testing.T, extraFrontmatter string) (string, error) {
	t.Helper()
	return compileHostUserWorkflowWithDetection(t, extraFrontmatter, false)
}

// compileHostUserWorkflowWithDetection is compileHostUserWorkflow with threat
// detection switched on or off.
func compileHostUserWorkflowWithDetection(t *testing.T, extraFrontmatter string, detection bool) (string, error) {
	t.Helper()
	dir := t.TempDir()
	markdown := "---\non: workflow_dispatch\npermissions:\n  contents: read\nruns-on: ubuntu-26.04\nengine: claude\n" +
		"sandbox:\n  agent:\n    runtime: host-user\n" + extraFrontmatter +
		fmt.Sprintf("safe-outputs:\n  add-comment:\n    target: \"1\"\n  threat-detection: %v\n---\n\nDo the thing.\n", detection)
	path := filepath.Join(dir, "host-user.md")
	require.NoError(t, os.WriteFile(path, []byte(markdown), 0o644))
	if err := NewCompiler().CompileWorkflow(path); err != nil {
		return "", err
	}
	lock, err := os.ReadFile(filepath.Join(dir, "host-user.lock.yml"))
	require.NoError(t, err)
	return string(lock), nil
}

// stepBlock returns the lines of the named step in the lock file.
func stepBlock(t *testing.T, lock, name string) string {
	t.Helper()
	start := strings.Index(lock, "      - name: "+name+"\n")
	require.GreaterOrEqual(t, start, 0, "step %q not found", name)
	rest := lock[start+1:]
	if end := strings.Index(rest, "\n      - name: "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func TestHostUserCompiledSteps(t *testing.T) {
	lock, err := compileHostUserWorkflow(t, "strict: false\n")
	require.NoError(t, err)

	t.Run("steps run in order around the agent", func(t *testing.T) {
		order := []string{
			"Start MCP Gateway",
			"Clean credentials",
			"Start inference proxy for the host-user sandbox",
			"Enter the host-user sandbox",
			"Execute Claude Code CLI",
			"Seal the host-user sandbox",
			"Stop inference proxy for the host-user sandbox",
			"Configure Git credentials\n        env:",
			"Upload agent artifacts",
		}
		last := -1
		for _, name := range order {
			idx := strings.LastIndex(lock, "      - name: "+name)
			require.GreaterOrEqual(t, idx, 0, "step %q not found", name)
			assert.Greater(t, idx, last, "step %q is out of order", name)
			last = idx
		}
	})

	t.Run("only the proxy step holds the API key", func(t *testing.T) {
		proxy := stepBlock(t, lock, "Start inference proxy for the host-user sandbox")
		assert.Contains(t, proxy, "ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}")
		assert.Contains(t, proxy, "-p 127.0.0.1:10001:10001")
		assert.Contains(t, proxy, "ghcr.io/github/gh-aw-firewall/api-proxy:")

		agent := stepBlock(t, lock, "Execute Claude Code CLI")
		assert.NotContains(t, agent, "secrets.", "the agent step must not reference any secret")
		assert.NotContains(t, agent, "github.token")
		assert.Contains(t, agent, "ANTHROPIC_BASE_URL: http://127.0.0.1:10001")
	})

	t.Run("the engine runs through the sandbox helper", func(t *testing.T) {
		agent := stepBlock(t, lock, "Execute Claude Code CLI")
		assert.Contains(t, agent, `sudo -n bash "${RUNNER_TEMP}/gh-aw/actions/host_user_sandbox.sh" run "${gh_aw_sandbox_args[@]}"`)
		assert.Contains(t, agent, "--writable=/tmp/gh-aw/claude-debug.log")
		assert.Contains(t, agent, "--writable=/tmp/gh-aw/agent-step-summary.md")
		assert.Contains(t, agent, `--bind-ro=${RUNNER_TEMP}/gh-aw/mcp-config/mcp-servers.json`)
		assert.NotContains(t, agent, `--bind-ro=${RUNNER_TEMP}/gh-aw/mcp-config"`, "only the client config is shown, not the gateway's files")
		assert.Contains(t, agent, "| tee -a /tmp/gh-aw/agent-stdio.log")
		assert.Contains(t, agent, `printf '%s\n' "$GH_AW_HOST_USER_AGENT_COMMAND" > "${RUNNER_TEMP}/gh-aw/host-user-agent-command.sh"`)
		assert.Contains(t, agent, "GH_AW_HOST_USER_AGENT_COMMAND: ", "the engine command travels in the step env")
		assert.NotContains(t, agent, "for gh_aw_name in GH_AW_HOST_USER_AGENT_COMMAND", "the command itself is not forwarded")
		assert.NotContains(t, agent, " GH_AW_HOST_USER_AGENT_COMMAND ", "the command itself is not forwarded")
		assert.NotContains(t, agent, "awf ", "the agent must not run under AWF")
		assert.Contains(t, agent, " PATH ", "PATH must be forwarded so the engine finds node")
	})

	t.Run("the seal runs whatever the agent outcome", func(t *testing.T) {
		seal := stepBlock(t, lock, "Seal the host-user sandbox")
		assert.Contains(t, seal, "if: always()")
		assert.Contains(t, seal, "host_user_sandbox.sh\" seal")
	})

	t.Run("the proxy image is pre-pulled", func(t *testing.T) {
		pull := stepBlock(t, lock, "Download container images")
		assert.Contains(t, pull, "ghcr.io/github/gh-aw-firewall/api-proxy:")
		assert.NotContains(t, pull, "gh-aw-firewall/squid", "AWF itself is not used by the agent job")
	})
}

func TestHostUserRefusedInStrictMode(t *testing.T) {
	_, err := compileHostUserWorkflow(t, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not restrict network egress")
}

// The threat-detection job still runs under AWF with host-user, so it keeps its
// firewall log collection.
func TestHostUserKeepsDetectionUnderAWF(t *testing.T) {
	lock, err := compileHostUserWorkflowWithDetection(t, "strict: false\n", true)
	require.NoError(t, err)

	detection := lock[strings.Index(lock, "\n  detection:\n"):]
	assert.Contains(t, detection, "awf ", "detection must run under AWF")
	assert.Contains(t, detection, detectionFirewallLogsDir+"/logs/", "detection must keep uploading its firewall logs")
	assert.NotContains(t, detection, "host_user_sandbox.sh", "detection must not use the host-user sandbox")
}
