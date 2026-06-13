package s3

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	s3fern "github.com/Method-Security/methodaws/generated/go/s3"

	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// permutationSuffixes mirrors the in-process bucket enumerator's seed expansion
// patterns so seed-based discovery behaves consistently across both code paths.
var permutationSuffixes = []string{
	"", "-backup", "-prod", "-production", "-staging", "-stage", "-dev", "-test",
	"-logs", "-log", "-artifacts", "-assets", "-static", "-public", "-private",
	"-data", "-files", "-uploads", "-media", "-archive", "-backups", "-cdn",
	"-web", "-app", "-config", "-terraform", "-tfstate", "-lambda", "-builds",
	"-releases",
}

// seedProbeRegions is a bounded default region set used for seed discovery when
// no explicit regions are configured, keeping the number of probe calls in check.
var seedProbeRegions = []string{"us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"}

const (
	defaultMaxCandidates = 50
	maxCandidatesCap     = 500
)

var (
	nonAlnumRun     = regexp.MustCompile(`[^a-z0-9]+`)
	nonDottedRun    = regexp.MustCompile(`[^a-z0-9.-]+`)
	leadingWww      = regexp.MustCompile(`^www\.`)
	validBucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
)

// normalizeSeedVariants derives candidate base names from a seed (org name, domain
// or URL), mirroring the in-process enumerator's variant generation.
func normalizeSeedVariants(targetSeed string) []string {
	seed := strings.ToLower(strings.TrimSpace(targetSeed))
	if strings.Contains(seed, "://") {
		seed = strings.SplitN(seed, "://", 2)[1]
	}
	seed = strings.SplitN(seed, "/", 2)[0]
	seed = strings.SplitN(seed, ":", 2)[0]
	seed = strings.Trim(seed, ".")
	seed = leadingWww.ReplaceAllString(seed, "")

	compact := strings.Trim(nonAlnumRun.ReplaceAllString(seed, "-"), "-")
	noTld := compact
	if strings.Contains(seed, ".") {
		labels := []string{}
		for _, label := range strings.Split(seed, ".") {
			if label != "" {
				labels = append(labels, label)
			}
		}
		if len(labels) >= 2 {
			noTld = strings.Trim(nonAlnumRun.ReplaceAllString(labels[len(labels)-2], "-"), "-")
		}
	}

	variants := []string{compact, noTld, strings.ReplaceAll(compact, "-", ""), strings.ReplaceAll(noTld, "-", "")}
	if strings.Contains(seed, ".") {
		dotted := strings.Trim(nonDottedRun.ReplaceAllString(seed, "-"), "-.")
		variants = append([]string{dotted}, variants...)
	}

	return dedupeNonEmpty(variants)
}

func dedupeNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// candidateNames expands seed variants with permutation suffixes, capping the
// result at maxCandidates (clamped to [1, 500]).
func candidateNames(targetSeed string, maxCandidates int) []string {
	if maxCandidates < 1 {
		maxCandidates = 1
	}
	if maxCandidates > maxCandidatesCap {
		maxCandidates = maxCandidatesCap
	}

	candidates := make([]string, 0, maxCandidates)
	seen := make(map[string]struct{}, maxCandidates)
	for _, base := range normalizeSeedVariants(targetSeed) {
		for _, suffix := range permutationSuffixes {
			name := base + suffix
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			// Skip invalid names here so they don't consume a cap slot and
			// starve real candidates further down the permutation list.
			if !isValidBucketName(name) {
				continue
			}
			candidates = append(candidates, name)
			if len(candidates) >= maxCandidates {
				return candidates
			}
		}
	}
	return candidates
}

func isValidBucketName(name string) bool {
	return len(name) >= 3 && len(name) <= 63 &&
		validBucketName.MatchString(name) &&
		!strings.Contains(name, "..") &&
		!strings.Contains(name, ".-") &&
		!strings.Contains(name, "-.")
}

// enumerateBySeed generates candidate bucket names from the seed and runs the full
// external enumeration against each candidate that resolves to an existing bucket.
func enumerateBySeed(ctx context.Context, config s3fern.S3ExternalConfig) (*s3fern.ExternalS3BucketResult, []string) {
	log := svc1log.FromContext(ctx)
	result := &s3fern.ExternalS3BucketResult{}
	errors := []string{}

	maxCandidates := defaultMaxCandidates
	if config.MaxCandidates != nil && *config.MaxCandidates > 0 {
		maxCandidates = *config.MaxCandidates
	}

	candidates := candidateNames(*config.TargetSeed, maxCandidates)
	log.Info("Starting seed-based S3 bucket discovery",
		svc1log.SafeParam("targetSeed", *config.TargetSeed),
		svc1log.SafeParam("candidateCount", len(candidates)))

	regionsToCheck := config.Regions
	if len(regionsToCheck) == 0 {
		regionsToCheck = seedProbeRegions
	}

	for _, name := range candidates {
		for _, region := range regionsToCheck {
			exists, err := bucketExists(ctx, region, name)
			if err != nil {
				// Probe errors are non-fatal during discovery; try the next region.
				continue
			}
			if !exists {
				continue
			}
			bucketURL := fmt.Sprintf("https://%s.s3.amazonaws.com", name)
			functionResult, functionErrors := externalS3Region(ctx, bucketURL, name, region)
			if functionResult != nil {
				result.ExternalBuckets = append(result.ExternalBuckets, functionResult.ExternalBuckets...)
			}
			errors = append(errors, functionErrors...)
			break
		}
	}

	log.Info("Completed seed-based S3 bucket discovery",
		svc1log.SafeParam("targetSeed", *config.TargetSeed),
		svc1log.SafeParam("bucketsFound", len(result.ExternalBuckets)))

	return result, errors
}
