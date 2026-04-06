// Package imageref parses Docker image references.
package imageref

import (
	"fmt"
	"strings"
)

// Parse parses a Docker image reference into (domain, repository, tag_or_digest).
// Matches the Rust py_parse_image_ref behavior.
func Parse(image string) (domain, repository, tagOrDigest string, err error) {
	if image == "" {
		return "", "", "", fmt.Errorf("empty image reference")
	}

	// Check for digest
	if idx := strings.Index(image, "@"); idx >= 0 {
		tagOrDigest = image[idx+1:]
		image = image[:idx]
	}

	// Check for tag (only if no digest)
	if tagOrDigest == "" {
		// Find last colon that's not part of a port
		if idx := strings.LastIndex(image, ":"); idx >= 0 {
			// Ensure it's a tag, not a port (port would have / before it)
			afterColon := image[idx+1:]
			if !strings.Contains(afterColon, "/") {
				tagOrDigest = afterColon
				image = image[:idx]
			}
		}
	}

	if tagOrDigest == "" {
		tagOrDigest = "latest"
	}

	// Split domain from path
	// Domain contains a dot, colon, or is "localhost"
	if idx := strings.Index(image, "/"); idx >= 0 {
		potential := image[:idx]
		if strings.Contains(potential, ".") || strings.Contains(potential, ":") || potential == "localhost" {
			domain = potential
			repository = image[idx+1:]
		} else {
			domain = "docker.io"
			repository = image
		}
	} else {
		domain = "docker.io"
		repository = "library/" + image
	}

	// Normalize docker.io library prefix
	if domain == "docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}

	return domain, repository, tagOrDigest, nil
}
