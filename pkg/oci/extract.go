// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/safearchive"
)

// OCILayout represents the OCI image layout.
type OCILayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

// OCIIndex represents the OCI index.json.
type OCIIndex struct {
	SchemaVersion int `json:"schemaVersion"`
	Manifests     []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	} `json:"manifests"`
}

// ExtractAlgorithm extracts the algorithm file and optionally requirements.txt from an OCI image directory.
func ExtractAlgorithm(ctx context.Context, logger *slog.Logger, ociDir, destPath, algoType string) (string, string, error) {
	// Read index.json to find manifest
	indexPath := filepath.Join(ociDir, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read index.json: %w", err)
	}

	var index OCIIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		return "", "", fmt.Errorf("failed to parse index.json: %w", err)
	}

	if len(index.Manifests) == 0 {
		return "", "", fmt.Errorf("no manifests found in index.json")
	}

	// Get the first manifest digest
	manifestDigest := index.Manifests[0].Digest
	manifestPath := filepath.Join(ociDir, "blobs", strings.Replace(manifestDigest, ":", "/", 1))

	// Read manifest to find layers
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return "", "", fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Extract layers to find algorithm files
	logger.Debug("found layers in manifest", "count", len(manifest.Layers))
	var algorithmPath string
	var requirementsPath string
	var allSeenFiles []string
	extractionRoot, err := safearchive.OpenRoot(destPath, 0o700)
	if err != nil {
		return "", "", fmt.Errorf("failed to open extraction root: %w", err)
	}
	defer extractionRoot.Close()

	// Process layers in reverse order (top layers first)
	for i := len(manifest.Layers) - 1; i >= 0; i-- {
		layer := manifest.Layers[i]
		layerPath := filepath.Join(ociDir, "blobs", strings.Replace(layer.Digest, ":", "/", 1))

		// Try to extract and find algorithm file
		algoP, reqP, seenFiles, err := extractLayerAndFindAlgorithm(logger, layerPath, extractionRoot, destPath, algoType)
		if len(seenFiles) > 0 {
			allSeenFiles = append(allSeenFiles, seenFiles...)
		}

		if err != nil {
			logger.Warn("failed to extract layer", "digest", layer.Digest, "error", err)
			continue
		}

		if algoP != "" && algorithmPath == "" {
			algorithmPath = algoP
		}
		if reqP != "" && requirementsPath == "" {
			requirementsPath = reqP
		}

		// If we found both, we can stop
		if algorithmPath != "" && (algoType != "python" || requirementsPath != "") {
			break
		}
	}

	if algorithmPath == "" {
		return "", "", fmt.Errorf("no algorithm file found. Seen files: %v", allSeenFiles)
	}

	return algorithmPath, requirementsPath, nil
}

// extractLayerAndFindAlgorithm extracts a layer and searches for algorithm files.
func extractLayerAndFindAlgorithm(logger *slog.Logger, layerPath string, root *os.Root, destPath, algoType string) (string, string, []string, error) {
	// Open layer file
	layerFile, err := os.Open(layerPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to open layer: %w", err)
	}
	defer layerFile.Close()

	// Decompress gzip
	gzReader, err := gzip.NewReader(layerFile)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Read tar archive
	tarReader := tar.NewReader(gzReader)

	var algorithmPath string
	var requirementsPath string
	seenFiles := []string{}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", seenFiles, fmt.Errorf("failed to read tar header: %w", err)
		}

		logger.Debug("inspecting file in layer", "name", header.Name, "type", header.Typeflag)

		// Only regular files are executable or dependency inputs. Do not
		// reinterpret archive links or special files as regular files.
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		seenFiles = append(seenFiles, header.Name)

		// Check if this is an algorithm file or requirements.txt
		isAlgo := isAlgorithmFile(header.Name, header.Mode, algoType)
		isReq := filepath.Base(header.Name) == "requirements.txt"

		if isAlgo || isReq {
			cleanName, ok := cleanOCIEntryName(header.Name)
			if !ok {
				continue
			}

			targetPath := filepath.Join(destPath, cleanName)

			mode := os.FileMode(0o600)
			if isAlgo {
				mode = 0o700
			}
			if err := safearchive.WriteFile(root, cleanName, mode, tarReader); err != nil {
				return "", "", seenFiles, fmt.Errorf("failed to write file: %w", err)
			}

			if isAlgo && algorithmPath == "" {
				algorithmPath = targetPath
			}
			if isReq && requirementsPath == "" {
				requirementsPath = targetPath
			}
		}
	}

	return algorithmPath, requirementsPath, seenFiles, nil
}

// isAlgorithmFile checks if a file is likely an algorithm file based on its name, mode and expected algorithm type.
func isAlgorithmFile(filename string, mode int64, algoType string) bool {
	base := filepath.Base(filename)
	baseLower := strings.ToLower(base)

	// Common algorithm file names
	algorithmNames := []string{"algorithm", "main", "run", "execute"}

	switch algoType {
	case "python":
		return strings.HasSuffix(baseLower, ".py")
	case "wasm":
		return strings.HasSuffix(baseLower, ".wasm") || strings.HasSuffix(baseLower, ".wat")
	case "bin":
		// Ensure it doesn't have a known non-binary extension
		nonBinExts := []string{".py", ".wasm", ".wat", ".js", ".sh", ".csv", ".json", ".txt", ".md"}
		for _, ext := range nonBinExts {
			if strings.HasSuffix(baseLower, ext) {
				return false
			}
		}

		// Check for common names
		for _, name := range algorithmNames {
			if strings.Contains(baseLower, name) {
				return true
			}
		}
		// Check if it's executable (at least one 'x' bit set)
		return mode&0o111 != 0
	case "docker":
		// Docker algorithms are the whole image, this function shouldn't be used for them
		return false
	default:
		// Unknown or empty algoType - no generic fallback to ensure explicit type usage
		return false
	}
}

// ExtractDataset extracts dataset files from an OCI image directory.
func ExtractDataset(ociDir, destPath string) ([]string, error) {
	// Similar to ExtractAlgorithm but extracts all data files
	// Read index.json to find manifest
	indexPath := filepath.Join(ociDir, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read index.json: %w", err)
	}

	var index OCIIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("failed to parse index.json: %w", err)
	}

	if len(index.Manifests) == 0 {
		return nil, fmt.Errorf("no manifests found in index.json")
	}

	// Get the first manifest digest
	manifestDigest := index.Manifests[0].Digest
	manifestPath := filepath.Join(ociDir, "blobs", strings.Replace(manifestDigest, ":", "/", 1))

	// Read manifest to find layers
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	var datasetFiles []string
	extractionRoot, err := safearchive.OpenRoot(destPath, 0o700)
	if err != nil {
		return nil, fmt.Errorf("failed to open extraction root: %w", err)
	}
	defer extractionRoot.Close()

	// Extract all layers and collect dataset files
	// Iterate layers in reverse order to find user data first (usually in top layers)
	for i := len(manifest.Layers) - 1; i >= 0; i-- {
		layer := manifest.Layers[i]
		layerPath := filepath.Join(ociDir, "blobs", strings.Replace(layer.Digest, ":", "/", 1))

		files, err := extractLayerDataFiles(layerPath, extractionRoot, destPath)
		if err != nil {
			slog.Warn("error extracting layer", "digest", layer.Digest, "error", err)
			continue
		}
		datasetFiles = append(datasetFiles, files...)
	}

	if len(datasetFiles) == 0 {
		return nil, fmt.Errorf("no dataset files found in OCI image layers")
	}

	return datasetFiles, nil
}

// extractLayerDataFiles extracts data files from a layer.
func extractLayerDataFiles(layerPath string, root *os.Root, destPath string) ([]string, error) {
	layerFile, err := os.Open(layerPath)
	if err != nil {
		return nil, err
	}
	defer layerFile.Close()

	gzReader, err := gzip.NewReader(layerFile)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var extractedFiles []string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			continue
		}

		// Check if this is a data file
		if isDataFile(header.Name) {
			cleanName, ok := cleanOCIEntryName(header.Name)
			if !ok {
				continue
			}

			targetPath := filepath.Join(destPath, cleanName)

			if err := safearchive.WriteFile(root, cleanName, 0o600, tarReader); err != nil {
				return nil, err
			}

			extractedFiles = append(extractedFiles, targetPath)
		}
	}

	return extractedFiles, nil
}

func cleanOCIEntryName(name string) (string, bool) {
	if name == "" || strings.Contains(name, "\x00") || strings.Contains(name, "\\") || path.IsAbs(name) {
		return "", false
	}
	cleanName := path.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return "", false
	}
	return filepath.FromSlash(cleanName), true
}

// isDataFile checks if a file is likely a dataset file.
func isDataFile(filename string) bool {
	dataExts := []string{".csv", ".json", ".txt", ".parquet", ".arrow", ".dat", ".zip", ".tar", ".gz", ".tgz", ".tar.gz"}

	baseLower := strings.ToLower(filepath.Base(filename))

	for _, ext := range dataExts {
		if strings.HasSuffix(baseLower, ext) {
			return true
		}
	}

	return false
}
