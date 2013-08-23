package nosurf

func sContains(slice []string, s string) bool {
	// checks if the given slice contains the given string
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
