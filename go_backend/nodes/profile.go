package nodes

import "strings"

// PrepareProfile pins the requested TUN and blocks provider route replacement.
func PrepareProfile(profile, device string) string {
	var output strings.Builder
	block := false
	seenDev, routeNoPull := false, false
	for _, line := range strings.Split(strings.ReplaceAll(profile, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if block {
			output.WriteString(line + "\n")
			if strings.HasPrefix(lower, "</") {
				block = false
			}
			continue
		}
		fields := strings.Fields(trimmed)
		directive := strings.TrimLeft(lower, "-")
		switch {
		case strings.HasPrefix(lower, "<"):
			block = true
		case strings.HasPrefix(directive, "dev ") || directive == "dev":
			output.WriteString("dev " + device + "\n")
			seenDev = true
			continue
		case directive == "route-nopull":
			routeNoPull = true
		}
		output.WriteString(line + "\n")
	}
	if !seenDev {
		output.WriteString("dev " + device + "\n")
	}
	if !routeNoPull {
		output.WriteString("route-nopull\n")
	}
	return output.String()
}
