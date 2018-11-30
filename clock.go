package portal

import (
	"net/http"
	"time"
)

type TimeProvider interface {
	Unix(relative time.Duration) int64
	HTTP(relative time.Duration) string
}

type defaultTimeProvider struct{}

func (t defaultTimeProvider) Unix(relative time.Duration) int64 {
	return time.Now().Add(relative).Unix()
}

func (t defaultTimeProvider) HTTP(relative time.Duration) string {
	return time.Now().Add(relative).Format(http.TimeFormat)
}

var Clock TimeProvider = defaultTimeProvider{}
