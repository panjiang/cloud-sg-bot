package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func ParseDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("duration is empty")
	}
	if strings.HasSuffix(value, "d") || strings.HasSuffix(value, "w") {
		multiplier := 24 * time.Hour
		if strings.HasSuffix(value, "w") {
			multiplier = 7 * 24 * time.Hour
		}
		number := strings.TrimSpace(value[:len(value)-1])
		if number == "" {
			return 0, fmt.Errorf("missing duration value")
		}
		n, err := strconv.ParseFloat(number, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(n * float64(multiplier)), nil
	}
	return time.ParseDuration(value)
}
