// This file validates workflows that use sandbox.agent.runtime: host-user and
// refuses the combinations that runtime does not support.

package workflow

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/github/gh-aw/pkg/console"
	"github.com/github/gh-aw/pkg/constants"
	"github.com/github/gh-aw/pkg/sliceutil"
)

// hostUserIncompatibleRunnerLabels matches whole GitHub-hosted runner labels whose
// images lack run0 (systemd 256 or later), which the host-user runtime needs.
// ubuntu-latest and ubuntu-slim are still Ubuntu 24.04 (systemd 255).
var hostUserIncompatibleRunnerLabels = regexp.MustCompile(`(?:^|[\s\[,"'])(ubuntu-(?:22\.04|24\.04|latest|slim)(?:-arm)?|macos-[A-Za-z0-9.-]+|windows-[A-Za-z0-9.-]+)(?:$|[\s\],"'])`)

// hostUserUnsupportedAgentFields lists the sandbox.agent fields that configure
// AWF, which the host-user runtime does not use.
var hostUserUnsupportedAgentFields = []struct {
	field string
	isSet func(*AgentSandboxConfig) bool
}{
	{"command", func(a *AgentSandboxConfig) bool { return a.Command != "" }},
	{"args", func(a *AgentSandboxConfig) bool { return len(a.Args) > 0 }},
	{"env", func(a *AgentSandboxConfig) bool { return len(a.Env) > 0 }},
	{"mounts", func(a *AgentSandboxConfig) bool { return len(a.Mounts) > 0 }},
	{"memory", func(a *AgentSandboxConfig) bool { return a.Memory != "" }},
	{"config", func(a *AgentSandboxConfig) bool { return a.Config != nil }},
	{"allow-host-ports", func(a *AgentSandboxConfig) bool { return len(a.AllowHostPorts) > 0 }},
	{"model-fallback", func(a *AgentSandboxConfig) bool { return a.ModelFallback != nil }},
	{"token-steering", func(a *AgentSandboxConfig) bool { return a.TokenSteering != nil }},
	{"targets", func(a *AgentSandboxConfig) bool { return len(a.Targets) > 0 }},
	{"images", func(a *AgentSandboxConfig) bool { return len(a.Images) > 0 }},
	{"ca-cert", func(a *AgentSandboxConfig) bool { return a.CACert != "" }},
}

// validateHostUserRuntime refuses the workflow settings the host-user runtime
// cannot honor. It is a no-op for every other runtime.
func validateHostUserRuntime(workflowData *WorkflowData) error {
	if !isHostUserRuntime(workflowData) {
		return nil
	}
	const field = "sandbox.agent.runtime"
	value := string(AgentRuntimeHostUser)
	refuse := func(reason, suggestion string) error {
		return NewValidationError(field, value, reason, suggestion+"\n\nSee: "+string(constants.DocsSandboxURL))
	}

	agentConfig := getAgentConfig(workflowData)
	for _, f := range hostUserUnsupportedAgentFields {
		if f.isSet(agentConfig) {
			return refuse(
				fmt.Sprintf("sandbox.agent.%s is not supported with the host-user runtime", f.field),
				fmt.Sprintf("sandbox.agent.%s configures AWF, which the host-user runtime does not use. Remove it, or use another runtime.", f.field),
			)
		}
	}

	if err := validateHostUserInference(workflowData, refuse); err != nil {
		return err
	}

	runsOn := strings.TrimSpace(workflowData.RunsOn)
	if runsOn == "" {
		return refuse(
			"the host-user runtime needs an explicit runs-on with systemd 256 or later",
			"The default runner (ubuntu-latest) is Ubuntu 24.04, whose systemd has no run0. Set runs-on: ubuntu-26.04, or a self-hosted runner with systemd 256 or later.",
		)
	}
	if m := hostUserIncompatibleRunnerLabels.FindStringSubmatch(runsOn); m != nil {
		label := m[1]
		return refuse(
			fmt.Sprintf("the host-user runtime does not work on %s: it needs run0 (systemd 256 or later)", label),
			"Set runs-on: ubuntu-26.04, or a self-hosted runner with systemd 256 or later.",
		)
	}

	if isArcDindTopology(workflowData) {
		return refuse(
			"the host-user runtime is incompatible with runner.topology: arc-dind",
			"The host-user runtime creates a user on the runner VM with root, which ARC DinD runners do not provide. Remove runner.topology or use another runtime.",
		)
	}
	// isCliProxyNeeded is false whenever AWF is off, so check what asks for the proxy.
	if isGitHubCLIModeEnabled(workflowData) || isFeatureEnabled(constants.IntegrityReactionsFeatureFlag, workflowData) {
		return refuse(
			"the host-user runtime is incompatible with tools.github.mode: gh-proxy",
			"The CLI proxy is an AWF sidecar, which the host-user runtime does not start. Remove tools.github.mode: gh-proxy and the integrity-reactions feature, or use another runtime.",
		)
	}
	// The memory directories are the runner's, under /tmp/gh-aw, which the sandbox
	// can only read; making them writable would hand it more trees that runner-side
	// git later runs in.
	if workflowData.CacheMemoryConfig != nil && len(workflowData.CacheMemoryConfig.Caches) > 0 {
		return refuse(
			"the host-user runtime does not support tools.cache-memory yet",
			"The agent could not write to the cache-memory directory. Remove tools.cache-memory, or use another runtime.",
		)
	}
	if workflowData.RepoMemoryConfig != nil && len(workflowData.RepoMemoryConfig.Memories) > 0 {
		return refuse(
			"the host-user runtime does not support tools.repo-memory yet",
			"The agent could not write to the repo-memory checkout. Remove tools.repo-memory, or use another runtime.",
		)
	}
	if len(workflowData.Enclaves) > 0 {
		return refuse(
			"the host-user runtime is incompatible with enclaves",
			"Enclaves are an AWF subsystem, which the host-user runtime does not use. Remove the enclaves configuration, or use another runtime.",
		)
	}
	return nil
}

// warnHostUserEgress warns that the host-user runtime does not restrict network
// egress, so network.allowed is not enforced for the agent, and names the
// engine.env variables that won't reach the agent because they hold a secret.
func (c *Compiler) warnHostUserEgress(workflowData *WorkflowData) error {
	if !isHostUserRuntime(workflowData) {
		return nil
	}
	if workflowData.EngineConfig != nil {
		var dropped []string
		for _, name := range sliceutil.SortedKeys(workflowData.EngineConfig.Env) {
			if isSecretEnvValue(workflowData.EngineConfig.Env[name]) {
				dropped = append(dropped, name)
			}
		}
		if len(dropped) > 0 {
			fmt.Fprintln(os.Stderr, console.FormatWarningMessage(
				"sandbox.agent.runtime: host-user does not pass secrets to the agent, so these engine.env variables are dropped: "+
					strings.Join(dropped, ", ")+". Use an inference endpoint that needs no secret, and a placeholder for any key the engine insists on.",
			))
			c.IncrementWarningCount()
		}
	}
	fmt.Fprintln(os.Stderr, console.FormatWarningMessage(
		"sandbox.agent.runtime: host-user does not restrict network egress yet: "+
			"network.allowed is not enforced for the agent, which can reach any host the runner can.",
	))
	c.IncrementWarningCount()
	return nil
}

// hostUserUnsupportedBuiltinEngines are the built-in engines the host-user runtime
// does not run yet: their CLIs need secrets or AWF-only plumbing in the agent step.
var hostUserUnsupportedBuiltinEngines = []constants.EngineName{
	constants.CopilotEngine, constants.CodexEngine, constants.GeminiEngine, constants.PiEngine,
}

// validateHostUserInference checks that the agent can reach inference without a
// secret in the sandbox: either the Claude engine through the runner-side
// api-proxy, or any supported engine pointed with engine.env at an endpoint that
// needs no secret.
func validateHostUserInference(workflowData *WorkflowData, refuse func(reason, suggestion string) error) error {
	engineID := string(constants.DefaultEngine)
	if workflowData.EngineConfig != nil && workflowData.EngineConfig.ID != "" {
		engineID = workflowData.EngineConfig.ID
	}
	for _, unsupported := range hostUserUnsupportedBuiltinEngines {
		// By prefix too: the engine catalog resolves IDs such as codex-experimental
		// to the built-in runtime they start with.
		if strings.HasPrefix(engineID, string(unsupported)) {
			return refuse(
				fmt.Sprintf("the host-user runtime does not support engine: %s yet", engineID),
				"Use engine: claude, or an engine defined with engine.behaviors (such as OpenCode) pointed at an inference endpoint that needs no secret.",
			)
		}
	}
	for _, envVar := range []string{"OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"} {
		if !engineEnvHasNonEmptyValue(workflowData, envVar) {
			continue
		}
		value := strings.TrimSpace(workflowData.EngineConfig.Env[envVar])
		if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			return refuse(
				fmt.Sprintf("engine.env.%s must be a literal http(s) URL with the host-user runtime", envVar),
				"The agent talks to this endpoint directly from the sandbox, so it must be a plain URL that needs no secret.",
			)
		}
	}
	if hasCustomLLMAPITarget(workflowData) {
		return nil
	}
	if engineID != string(constants.ClaudeEngine) {
		return refuse(
			fmt.Sprintf("engine %s needs an inference endpoint with the host-user runtime", engineID),
			"The runner-side inference proxy only serves the Claude engine so far. Point the engine at an endpoint that needs no secret, such as a credential broker, with engine.env.OPENAI_BASE_URL or engine.env.ANTHROPIC_BASE_URL.",
		)
	}
	if provider := NewClaudeEngine().ResolveLLMProvider(workflowData); provider != LLMProviderAnthropic {
		return refuse(
			fmt.Sprintf("the host-user runtime supports only the anthropic inference provider for Claude (got %q)", provider),
			"Its runner-side inference proxy only holds an Anthropic API key so far. Remove engine.provider, or use another runtime.",
		)
	}
	if workflowData.EngineConfig.APITarget != "" {
		return refuse(
			"engine.api-target is not supported with the host-user runtime",
			"The agent reaches inference through a runner-side proxy for api.anthropic.com. Remove engine.api-target, or point engine.env.ANTHROPIC_BASE_URL at an endpoint that needs no secret.",
		)
	}
	return nil
}
