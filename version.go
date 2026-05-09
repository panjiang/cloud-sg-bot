package main

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func Version() string {
	if commit == "unknown" && date == "unknown" {
		return version
	}
	return version + " (" + commit + ", " + date + ")"
}
