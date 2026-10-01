// This file generates the steps of the host-user agent sandbox
// (sandbox.agent.runtime: host-user).
//
// In this runtime the agent does not run inside AWF. gh-aw's setup (actions,
// MCP gateway, image pulls) runs as the runner user as usual; then:
//
//  1. A runner-side inference proxy (AWF's api-proxy image, run standalone)
//     holds the engine's API key and listens on localhost.
//  2. A root step (host_user_sandbox.sh enter) creates the runner-sandbox user
//     with subordinate ids and the kvm group but no sudo, closes the runner's
//     home and grants the user the workspace.
//  3. The engine command runs as runner-sandbox via run0, in its own logind
//     session, with only the step's non-secret environment variables.
//  4. A seal step stops every process of the sandbox user and hands the
//     workspace back to the runner, before any later step reads it.
//
// Artifacts, safe outputs and the conclusion job run as the runner, as before.
// The agent works in the runner's checkout, so the safe outputs MCP server sees
// its changes. Network egress is not restricted in this runtime.

package workflow

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/github/gh-aw/pkg/constants"
	"github.com/github/gh-aw/pkg/logger"
)

var hostUserLog = logger.New("workflow:host_user_sandbox")

const (
	// hostUserSandboxScript is the root-side helper, installed by the setup action.
	hostUserSandboxScript = "${RUNNER_TEMP}/gh-aw/actions/host_user_sandbox.sh"

	// hostUserAgentCommandFile holds the engine command the sandbox runs. The
	// helper copies it to a root-owned location before running it.
	hostUserAgentCommandFile = "${RUNNER_TEMP}/gh-aw/host-user-agent-command.sh"

	// HostUserAgentCommandEnv is the step variable that carries the engine
	// command verbatim, so it is expanded only inside the sandbox. It is not
	// forwarded into the sandbox itself.
	HostUserAgentCommandEnv = "GH_AW_HOST_USER_AGENT_COMMAND"

	// hostUserAPIProxyContainer is the name of the runner-side inference proxy.
	hostUserAPIProxyContainer = "gh-aw-host-user-api-proxy"

	// hostUserAPIProxyLogLines is how much of the proxy's log the stop step shows.
	hostUserAPIProxyLogLines = 200

	// hostUserAPIProxyHealthTimeoutSeconds bounds the wait for the proxy to answer.
	hostUserAPIProxyHealthTimeoutSeconds = 60

	// hostUserPlaceholderAnthropicToken is what the agent authenticates with: the
	// proxy replaces it with the real key, the same placeholder AWF uses.
	hostUserPlaceholderAnthropicToken = "sk-ant-placeholder-key-for-credential-isolation"
)

// hostUserReadOnlyPaths are the runner-side files and directories the engine
// command reads. The runner's home is hidden in the sandbox, so the helper shows a
// root-owned snapshot of each at the same path, and nothing else of RUNNER_TEMP.
var hostUserReadOnlyPaths = []string{
	"${RUNNER_TEMP}/gh-aw/actions",
	// Only the client config: the rest of mcp-config is the gateway's.
	"${RUNNER_TEMP}/gh-aw/mcp-config/mcp-servers.json",
	// The MCP servers mounted as CLIs (mount_mcp_as_cli.cjs), when there are any.
	"${RUNNER_TEMP}/gh-aw/mcp-cli",
}

// hostUserAPIProxyImage returns the api-proxy image used as the inference proxy:
// the one AWF itself would use for the configured firewall version.
func hostUserAPIProxyImage(workflowData *WorkflowData) string {
	return defaultAWFImageForRole(awfImageRoleAPIProxy, getAWFImageTag(getFirewallConfig(workflowData)))
}

// hostUserUsesAPIProxy reports whether the agent reaches inference through the
// runner-side api-proxy, which holds the engine's API key: the Claude engine on
// Anthropic's API. Otherwise the workflow points the engine at an endpoint of its
// own with engine.env (OPENAI_BASE_URL / ANTHROPIC_BASE_URL) that needs no secret,
// such as a credential broker, and the agent talks to it directly.
func hostUserUsesAPIProxy(workflowData *WorkflowData) bool {
	return workflowData != nil && workflowData.EngineConfig != nil &&
		workflowData.EngineConfig.ID == string(constants.ClaudeEngine) &&
		!hasCustomLLMAPITarget(workflowData)
}

// hostUserAPIProxyBaseURL is where the sandbox reaches the inference proxy.
func hostUserAPIProxyBaseURL(provider LLMProvider) string {
	return fmt.Sprintf("http://127.0.0.1:%d", llmProviderProfileFor(provider).gatewayPort)
}

// hostUserSecretExpression matches the ways a GitHub Actions expression can
// reach a credential: the secrets context in any form (secrets.X, secrets['X'],
// toJSON(secrets)) and the job's GitHub token.
var hostUserSecretExpression = regexp.MustCompile(`\bsecrets\b|\bgithub\s*(?:\.\s*token\b|\[)`)

// hostUserEnvName is what a variable forwarded into the sandbox may be called;
// the names are spliced into the generated shell.
var hostUserEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// isSecretEnvValue reports whether an env value carries a credential, which must
// never be forwarded into the host-user sandbox.
func isSecretEnvValue(value string) bool {
	return strings.Contains(value, "${{") && hostUserSecretExpression.MatchString(value)
}

// applyHostUserAgentEnv adjusts the agent step environment for the host-user
// sandbox: every secret-bearing variable is dropped, since the step forwards its
// whole environment into the sandbox, and with the api-proxy (useAPIProxy) the
// engine is pointed at it with a placeholder credential.
func applyHostUserAgentEnv(env map[string]string, useAPIProxy bool) {
	for key, value := range env {
		if isSecretEnvValue(value) || !hostUserEnvName.MatchString(key) {
			hostUserLog.Printf("Dropping variable from the host-user agent step: %s", key)
			delete(env, key)
		}
	}
	if useAPIProxy {
		env["ANTHROPIC_BASE_URL"] = hostUserAPIProxyBaseURL(LLMProviderAnthropic)
		env["ANTHROPIC_AUTH_TOKEN"] = hostUserPlaceholderAnthropicToken
	}
}

// buildHostUserAgentCommand returns the step script that runs the engine command
// in the host-user sandbox. The caller passes the engine command itself in the
// step variable HostUserAgentCommandEnv. envNames are the variables of the step
// forwarded into the sandbox, writableFiles the pre-created files the engine
// writes, and logFile receives the engine's stdout (and stderr too, with
// mergeStderr) on the runner side.
func buildHostUserAgentCommand(envNames []string, writableFiles []string, logFile string, mergeStderr bool) string {
	names := slices.Clone(envNames)
	// The engine finds node and its CLI through the PATH the setup steps built.
	if !slices.Contains(names, "PATH") {
		names = append(names, "PATH")
	}
	slices.Sort(names)

	var b strings.Builder
	fmt.Fprintf(&b, "printf '%%s\\n' \"$%s\" > \"%s\"\n", HostUserAgentCommandEnv, hostUserAgentCommandFile)
	b.WriteString("# Only these variables reach the sandbox; none of them holds a secret.\n")
	b.WriteString("gh_aw_sandbox_args=()\n")
	fmt.Fprintf(&b, "for gh_aw_name in %s; do\n", strings.Join(names, " "))
	b.WriteString("  if [ -n \"${!gh_aw_name+x}\" ]; then gh_aw_sandbox_args+=(\"--setenv=${gh_aw_name}=${!gh_aw_name}\"); fi\n")
	b.WriteString("done\n")
	for _, file := range writableFiles {
		fmt.Fprintf(&b, "gh_aw_sandbox_args+=(\"--writable=%s\")\n", file)
	}
	for _, path := range hostUserReadOnlyPaths {
		fmt.Fprintf(&b, "if [ -e \"%s\" ]; then gh_aw_sandbox_args+=(\"--bind-ro=%s\"); fi\n", path, path)
	}
	redirect := ""
	if mergeStderr {
		redirect = " 2>&1"
	}
	fmt.Fprintf(&b, "sudo -n bash \"%s\" run \"${gh_aw_sandbox_args[@]}\" -- \"%s\"%s | tee -a %s", hostUserSandboxScript, hostUserAgentCommandFile, redirect, logFile)
	return b.String()
}

// generateHostUserPreAgentSteps writes the steps that start the inference proxy
// (when the engine uses it) and enter the sandbox, right before the engine runs.
func generateHostUserPreAgentSteps(yaml *strings.Builder, data *WorkflowData) {
	hostUserLog.Print("Generating host-user sandbox pre-agent steps")
	if hostUserUsesAPIProxy(data) {
		generateHostUserAPIProxyStartStep(yaml, data)
	}
	yaml.WriteString("      - name: Enter the host-user sandbox\n")
	fmt.Fprintf(yaml, "        run: sudo -n bash \"%s\" enter \"$(id -un)\" \"${GITHUB_WORKSPACE}\" \"${RUNNER_TEMP}\"\n", hostUserSandboxScript)
}

// generateHostUserAPIProxyStartStep writes the step that starts AWF's api-proxy
// on the runner, holding the Anthropic API key.
func generateHostUserAPIProxyStartStep(yaml *strings.Builder, data *WorkflowData) {
	provider := LLMProviderAnthropic
	profile := llmProviderProfileFor(provider)
	secretEnv := llmProviderSecretNames(provider)[0]
	image := resolveContainerImage(hostUserAPIProxyImage(data), data)

	yaml.WriteString("      - name: Start inference proxy for the host-user sandbox\n")
	yaml.WriteString("        env:\n")
	fmt.Fprintf(yaml, "          %s: %s\n", secretEnv, llmProviderSecretExpression(provider, data))
	yaml.WriteString("        run: |\n")
	yaml.WriteString("          set -euo pipefail\n")
	yaml.WriteString("          # The API key stays in this runner-side container; the sandbox only gets its localhost address.\n")
	fmt.Fprintf(yaml, "          docker run -d --name %s -p 127.0.0.1:%d:%d -e %s %s\n", hostUserAPIProxyContainer, profile.gatewayPort, profile.gatewayPort, secretEnv, image)
	fmt.Fprintf(yaml, "          for _ in $(seq %d); do\n", hostUserAPIProxyHealthTimeoutSeconds)
	fmt.Fprintf(yaml, "            if curl -fsS -o /dev/null %s/health; then echo \"Inference proxy is ready\"; exit 0; fi\n", hostUserAPIProxyBaseURL(provider))
	yaml.WriteString("            sleep 1\n")
	yaml.WriteString("          done\n")
	fmt.Fprintf(yaml, "          docker logs %s >&2 || true\n", hostUserAPIProxyContainer)
	fmt.Fprintf(yaml, "          echo \"::error::The inference proxy did not become healthy within %d seconds\"\n", hostUserAPIProxyHealthTimeoutSeconds)
	yaml.WriteString("          exit 1\n")
}

// generateHostUserPostAgentSteps writes the steps that seal the sandbox and stop
// the inference proxy. They run whatever the outcome of the agent step, before
// any later step reads what the agent left.
func generateHostUserPostAgentSteps(yaml *strings.Builder, data *WorkflowData) {
	hostUserLog.Print("Generating host-user sandbox post-agent steps")
	yaml.WriteString("      - name: Seal the host-user sandbox\n")
	yaml.WriteString("        if: always()\n")
	fmt.Fprintf(yaml, "        run: sudo -n bash \"%s\" seal\n", hostUserSandboxScript)
	if !hostUserUsesAPIProxy(data) {
		return
	}

	yaml.WriteString("      - name: Stop inference proxy for the host-user sandbox\n")
	yaml.WriteString("        if: always()\n")
	yaml.WriteString("        continue-on-error: true\n")
	yaml.WriteString("        run: |\n")
	yaml.WriteString("          echo \"::group::Inference proxy log\"\n")
	fmt.Fprintf(yaml, "          docker logs --tail %d %s 2>&1 || true\n", hostUserAPIProxyLogLines, hostUserAPIProxyContainer)
	yaml.WriteString("          echo \"::endgroup::\"\n")
	fmt.Fprintf(yaml, "          docker rm -f %s || true\n", hostUserAPIProxyContainer)
}
