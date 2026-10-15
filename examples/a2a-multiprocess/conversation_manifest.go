// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/llmruntime"
)

type modelDigestPolicy struct {
	DirectSHA256   string
	ManifestCID    string
	ManifestSHA256 string
	Repo           string
	Revision       string
	File           string
}

type conversationModelConfig struct {
	GGUFPath   string
	GGUFPolicy modelDigestPolicy
	Bundle     llmruntime.ModelBundleConfig
}

func (config conversationModelConfig) usesBundle() bool {
	return config.Bundle.RootPath != "" || config.Bundle.ManifestPath != "" ||
		config.Bundle.ManifestCID != "" || config.Bundle.ManifestSHA256 != ""
}

func agentAModelConfig(opts options) conversationModelConfig {
	return conversationModelConfig{
		GGUFPath: opts.agentAGGUFPath, GGUFPolicy: agentAModelPolicy(opts),
		Bundle: llmruntime.ModelBundleConfig{
			RootPath: opts.agentAModelDir, ManifestPath: opts.agentAModelManifest,
			ManifestCID: opts.agentAModelManifestCID, ManifestSHA256: opts.agentAModelManifestSHA256,
			KuboAPIURL: opts.kuboAPIURL,
		},
	}
}

func agentBModelConfig(opts options) conversationModelConfig {
	return conversationModelConfig{
		GGUFPath: opts.agentBGGUFPath, GGUFPolicy: agentBModelPolicy(opts),
		Bundle: llmruntime.ModelBundleConfig{
			RootPath: opts.agentBModelDir, ManifestPath: opts.agentBModelManifest,
			ManifestCID: opts.agentBModelManifestCID, ManifestSHA256: opts.agentBModelManifestSHA256,
			KuboAPIURL: opts.kuboAPIURL,
		},
	}
}

func agentAModelPolicy(opts options) modelDigestPolicy {
	return modelDigestPolicy{
		DirectSHA256: opts.agentAGGUFSHA256, ManifestCID: opts.agentAGGUFManifestCID,
		ManifestSHA256: opts.agentAGGUFManifestSHA256, Repo: opts.agentAGGUFRepo,
		Revision: opts.agentAGGUFRevision, File: opts.agentAGGUFFile,
	}
}

func agentBModelPolicy(opts options) modelDigestPolicy {
	return modelDigestPolicy{
		DirectSHA256: opts.agentBGGUFSHA256, ManifestCID: opts.agentBGGUFManifestCID,
		ManifestSHA256: opts.agentBGGUFManifestSHA256, Repo: opts.agentBGGUFRepo,
		Revision: opts.agentBGGUFRevision, File: opts.agentBGGUFFile,
	}
}

func resolveModelDigest(ctx context.Context, policy modelDigestPolicy, kuboAPIURL string) (string, int64, error) {
	if policy.ManifestCID == "" {
		return policy.DirectSHA256, 0, nil
	}
	manifest, err := llmruntime.ResolvePinnedGGUFManifest(ctx, llmruntime.PinnedGGUFManifestConfig{
		CID: policy.ManifestCID, ManifestSHA256: policy.ManifestSHA256,
		KuboAPIURL: kuboAPIURL, ExpectedRepo: policy.Repo,
		ExpectedRevision: policy.Revision, ExpectedPath: policy.File,
	})
	if err != nil {
		return "", 0, err
	}
	return manifest.ModelSHA256, manifest.Size, nil
}

func modelPolicyArgs(prefix string, policy modelDigestPolicy) []string {
	if policy.ManifestCID == "" {
		return []string{"--" + prefix + "-sha256", policy.DirectSHA256}
	}
	return []string{
		"--" + prefix + "-manifest-cid", policy.ManifestCID,
		"--" + prefix + "-manifest-sha256", policy.ManifestSHA256,
		"--" + prefix + "-repo", policy.Repo,
		"--" + prefix + "-revision", policy.Revision,
		"--" + prefix + "-file", policy.File,
	}
}

func conversationModelArgs(opts options, prefix string, config conversationModelConfig) []string {
	args := []string{"--kubo-api-url", opts.kuboAPIURL, "--llm-request-timeout", conversationRequestTimeout(opts).String()}
	if opts.llamaServerPath != "" || opts.llamaServerSHA256 != "" {
		args = append(args, "--llama-server-path", opts.llamaServerPath, "--llama-server-sha256", opts.llamaServerSHA256)
	}
	if opts.pythonPath != "" || opts.pythonSHA256 != "" || opts.pythonSitePackages != "" {
		args = append(args, "--python-path", opts.pythonPath, "--python-sha256", opts.pythonSHA256,
			"--python-site-packages", opts.pythonSitePackages)
	}
	if opts.transformersDevice != "" {
		args = append(args, "--transformers-device", opts.transformersDevice)
	}
	if !config.usesBundle() {
		args = append(args, "--"+prefix+"-gguf-path", config.GGUFPath)
		return append(args, modelPolicyArgs(prefix+"-gguf", config.GGUFPolicy)...)
	}
	args = append(args, "--"+prefix+"-model-dir", config.Bundle.RootPath,
		"--"+prefix+"-model-manifest-sha256", config.Bundle.ManifestSHA256)
	if config.Bundle.ManifestCID != "" {
		return append(args, "--"+prefix+"-model-manifest-cid", config.Bundle.ManifestCID)
	}
	return append(args, "--"+prefix+"-model-manifest", config.Bundle.ManifestPath)
}
