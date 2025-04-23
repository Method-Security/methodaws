package utils

// GetGeneralRegions returns a list of known AWS regions.
func GetGeneralRegions() []string {
	return []string{
		"us-east-1",    // N. Virginia (default legacy region, can omit region in URLs)
		"us-east-2",    // Ohio
		"us-west-1",    // N. California
		"us-west-2",    // Oregon
		"ca-central-1", // Canada (Central)

		"eu-west-1",    // Ireland
		"eu-west-2",    // London
		"eu-west-3",    // Paris
		"eu-central-1", // Frankfurt
		"eu-north-1",   // Stockholm
		"eu-south-1",   // Milan
		"eu-south-2",   // Spain
		"eu-central-2", // Zurich

		"ap-northeast-1", // Tokyo
		"ap-northeast-2", // Seoul
		"ap-northeast-3", // Osaka
		"ap-southeast-1", // Singapore
		"ap-southeast-2", // Sydney
		"ap-southeast-3", // Jakarta
		"ap-southeast-4", // Melbourne
		"ap-south-1",     // Mumbai
		"ap-south-2",     // Hyderabad
		"ap-east-1",      // Hong Kong

		"me-south-1",   // Bahrain
		"me-central-1", // UAE

		"sa-east-1",  // São Paulo
		"af-south-1", // Cape Town
	}
}
