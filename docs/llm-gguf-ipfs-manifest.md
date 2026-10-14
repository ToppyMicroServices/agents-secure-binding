# Pinned GGUF manifests over IPFS

The `llm-conversation` example can obtain an expected GGUF digest from a small
IPFS manifest. The verifier first approves the manifest's exact SHA-256, CID,
Hugging Face repository, commit, and file path in local policy. ASB fetches the
manifest through a local Kubo node, verifies its bytes, and compares the GGUF
file with the digest and size it contains before starting `llama-server`.

IPFS DHT lookup helps find the manifest. It does not decide which manifest is
trusted. The expected manifest SHA-256 and source identity must come from a
reviewed source outside the DHT. Do not calculate the expected value from a
manifest just fetched for the same run.

## Prepare and approve a manifest

For a Hugging Face GGUF, select the exact model repository, its full 40-character
commit, and the GGUF path at that commit. Use the Hub's file metadata to check
the file's LFS SHA-256 and size. The `huggingface_hub` API exposes these through
[`model_info(..., files_metadata=True)`](https://huggingface.co/docs/huggingface_hub/package_reference/hf_api).
Compare the SHA-256 with a downloaded copy of that same GGUF. A converted or
quantized GGUF has its own digest; the source Safetensors digest does not apply.

Create a UTF-8 JSON file with exactly these fields:

```json
{
  "schema": "asb.huggingface-gguf/v1",
  "repo": "owner/model",
  "revision": "0123456789abcdef0123456789abcdef01234567",
  "path": "weights/model.gguf",
  "sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "size": 12345
}
```

The values above are placeholders. The revision must be a full immutable
commit, not `main` or a tag. The digest is SHA-256 of the GGUF's complete byte
stream. This version supports one `.gguf` file; adapters and separate shards
are outside its scope.

Add the approved file as a raw block with Kubo, for example
`ipfs block put --pin model-manifest.json`. Record its returned CID and the
SHA-256 of the exact JSON bytes in the verifier's local policy. Kubo's current
[`block put` command](https://docs.ipfs.tech/reference/kubo/cli/#ipfs-block-put)
uses a raw CIDv1 by default. ASB accepts only a raw CIDv1 with a full SHA-256
multihash and checks that its digest equals the separately supplied manifest
SHA-256. Keep at least one provider available for the CID. Public IPFS provider
advertisements and lookups can reveal interest in the CID, so use this path
only for non-secret model manifests.

For each agent, pass the GGUF path, approved manifest CID and digest, and the
expected Hugging Face source fields. The flags for Agent A are shown below;
Agent B uses the corresponding `--agent-b-*` flags.

```sh
--agent-a-gguf-path /absolute/path/to/model.gguf \
--agent-a-gguf-manifest-cid "$APPROVED_CID" \
--agent-a-gguf-manifest-sha256 "sha256:$APPROVED_MANIFEST_SHA256" \
--agent-a-gguf-repo owner/model \
--agent-a-gguf-revision 0123456789abcdef0123456789abcdef01234567 \
--agent-a-gguf-file weights/model.gguf \
--kubo-api-url http://127.0.0.1:5001
```

Use the existing `--llama-server-path` and `--llama-server-sha256` flags as
well. The manifest flags replace, rather than accompany, that agent's direct
`--agent-a-gguf-sha256` or `--agent-b-gguf-sha256` flag. Kubo's RPC must stay on
loopback; it has administrative control over the local node. ASB limits the
response to 64 KiB and rejects a missing block, unexpected source identity,
GGUF size or digest mismatch, or malformed manifest before launching the model
server.

The manifest records an asserted Hugging Face source. ASB does not query the
Hub during inference or verify that the model publisher signed the repository.
The operator must review the Hub metadata before approving the manifest. An
approved manifest plus a matching local GGUF verifies the selected local file
bytes under the existing host trust assumptions. It does not prove to another
agent which weights ran, and it cannot prove which weights an
external API used. External API endpoints remain rejected until a separate
verifiable runtime evidence format is defined and bound to the request.
