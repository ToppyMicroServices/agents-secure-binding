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
