package s3

import (
	"net"
	"net/url"
	"strings"
)

// parseBucketURL extracts the S3 bucket name and (if derivable) the region
// from common S3 URL forms and custom domains (CNAMEs) pointing to S3.
//
// Supported examples:
//   - https://bucket.s3.us-east-1.amazonaws.com
//   - https://bucket.s3.amazonaws.com
//   - https://sub.domain.bucket.s3.us-east-1.amazonaws.com (buckets with subdomains)
//   - https://s3.us-east-1.amazonaws.com/bucket
//   - https://s3.amazonaws.com/bucket
//   - http://bucket.s3-website-us-east-1.amazonaws.com
//   - https://bucket.s3-accelerate.amazonaws.com
//   - https://custom-domain.example.com (CNAME to S3)
//   - (no scheme) bucket.s3.us-west-2.amazonaws.com
//
// Region rules:
//   - Virtual-hosted regional (bucket.s3.<region>.*) → region extracted
//   - Path-style regional (s3.<region>.* /bucket)   → region extracted
//   - Global endpoints (s3.amazonaws.com, s3-accelerate) → region empty
//   - Website endpoints (s3-website-<region>) → region extracted
//   - Custom domains → region empty (not derivable from URL)
//
// Returns: (bucketName, region). Region may be "" if not derivable.
func parseBucketURL(raw string) (string, string) {
	if raw == "" {
		return "", ""
	}

	// Ensure we can parse even if scheme is missing
	u := ensureURL(raw)

	// Strip userinfo, port; isolate host labels and first path segment
	host := strings.ToLower(u.Host)
	if host == "" {
		return "", ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	labels := strings.Split(host, ".")

	// Check if this is a standard AWS endpoint
	isAwsEndpoint := false
	if len(labels) >= 2 {
		domain := strings.Join(labels[len(labels)-2:], ".") // "amazonaws.com" or "amazonaws.com.cn"
		if domain == "amazonaws.com" || domain == "amazonaws.com.cn" {
			isAwsEndpoint = true
		}
	}

	// If not a standard AWS endpoint, treat as custom domain (CNAME) pointing to S3
	if !isAwsEndpoint {
		// For custom domains, the entire host is typically the bucket name
		// and we can't determine the region from the URL
		return cleanupBucket(host), ""
	}

	// For AWS endpoints, ensure we have enough labels to process
	if len(labels) < 3 {
		return "", ""
	}

	// First path segment (for path-style)
	pathSeg := firstPathSegment(u.Path)

	// ----- Patterns -----

	// 1) Path-style regional: s3.<region>.amazonaws.com / bucket
	//    Also handles dualstack: s3.dualstack.<region>.amazonaws.com / bucket
	if labels[0] == "s3" || (labels[0] == "s3" && len(labels) >= 2 && labels[1] == "dualstack") || labels[0] == "s3-dualstack" {
		if pathSeg == "" {
			return "", ""
		}
		region := ""
		// s3.<region>....  -> region is labels[1]
		// s3.dualstack.<region>.... OR s3-dualstack.<region>.... -> region is labels[2]
		if labels[0] == "s3" && len(labels) >= 4 && labels[1] != "amazonaws" {
			region = labels[1]
		} else if (labels[0] == "s3" && len(labels) >= 5 && labels[1] == "dualstack") ||
			(labels[0] == "s3-dualstack" && len(labels) >= 5) {
			// s3.dualstack.<region>.amazonaws.com
			// s3-dualstack.<region>.amazonaws.com
			region = labels[2]
		} else {
			// Global path-style (s3.amazonaws.com / bucket) or unrecognized
			region = ""
		}
		return cleanupBucket(pathSeg), region
	}

	// Check for virtual-hosted style by finding .s3. pattern
	// This handles bucket names with subdomains like sub.domain.bucket.s3.region.amazonaws.com
	s3Index := findS3Index(labels)
	if s3Index >= 0 {
		// Extract bucket name (everything before .s3.)
		bucketParts := labels[:s3Index]
		bucket := strings.Join(bucketParts, ".")

		// Check what comes after .s3.
		if s3Index+1 < len(labels) {
			// 2) Virtual-hosted, regional: bucket.s3.<region>.amazonaws.com
			if s3Index+3 < len(labels) && labels[s3Index+2] == "amazonaws" {
				region := labels[s3Index+1]
				return cleanupBucket(bucket), region
			}
			// 3) Virtual-hosted, global: bucket.s3.amazonaws.com
			if s3Index+2 < len(labels) && labels[s3Index+1] == "amazonaws" {
				return cleanupBucket(bucket), ""
			}
		}
	}

	// 4) Website endpoints: bucket.s3-website-<region>.amazonaws.com
	//    Look for s3-website- pattern in any label position (to handle bucket subdomains)
	for i, label := range labels {
		if strings.HasPrefix(label, "s3-website-") {
			if i >= 1 && i+2 < len(labels) && labels[i+1] == "amazonaws" {
				bucketParts := labels[:i]
				bucket := strings.Join(bucketParts, ".")
				region := strings.TrimPrefix(label, "s3-website-")
				return cleanupBucket(bucket), region
			}
		}
	}

	// 5) Accelerate endpoints: bucket.s3-accelerate.amazonaws.com (or ...dualstack...)
	//    Look for s3-accelerate pattern in any label position (to handle bucket subdomains)
	for i, label := range labels {
		if label == "s3-accelerate" || strings.HasPrefix(label, "s3-accelerate") {
			if i >= 1 && i+2 < len(labels) && labels[i+1] == "amazonaws" {
				bucketParts := labels[:i]
				bucket := strings.Join(bucketParts, ".")
				return cleanupBucket(bucket), ""
			}
		}
	}

	// 6) Legacy global path-style: s3.amazonaws.com/bucket
	if strings.EqualFold(host, "s3.amazonaws.com") || strings.EqualFold(host, "s3-external-1.amazonaws.com") {
		if pathSeg == "" {
			return "", ""
		}
		return cleanupBucket(pathSeg), ""
	}

	// Not recognized as S3 bucket URL
	return "", ""
}

func ensureURL(raw string) *url.URL {
	// Add scheme if missing so url.Parse sees Host
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Fallback minimal parse
		return &url.URL{Host: raw}
	}
	return u
}

func firstPathSegment(p string) string {
	if p == "" {
		return ""
	}
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ""
	}
	seg := p
	if i := strings.IndexByte(p, '/'); i >= 0 {
		seg = p[:i]
	}
	// ignore query/fragment (already stripped by url.Parse)
	return seg
}

// findS3Index finds the index of "s3" label in virtual-hosted style URLs
// Returns -1 if "s3" is not found at an appropriate position
func findS3Index(labels []string) int {
	for i, label := range labels {
		if label == "s3" {
			// Make sure this is a virtual-hosted pattern, not a path-style one
			// Virtual-hosted: bucket[.subdomain].s3[.region].amazonaws.com
			// Path-style: s3[.region].amazonaws.com/bucket
			if i > 0 { // s3 should not be the first label for virtual-hosted
				return i
			}
		}
	}
	return -1
}

func cleanupBucket(b string) string {
	// Defensive cleanup; bucket DNS-style names shouldn't contain '?' or trailing '/'
	b = strings.TrimSpace(b)
	b = strings.TrimSuffix(b, "/")
	if i := strings.IndexByte(b, '?'); i >= 0 {
		b = b[:i]
	}
	return b
}
