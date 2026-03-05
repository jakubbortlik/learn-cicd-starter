package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)


func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input http.Header
		wantVal string
		wantErr error
	}{
		"simple": {
			input: http.Header{"Authorization": []string{"ApiKey NcvXrl"}},
			wantVal: "NcvXrl",
			wantErr: nil,
		},
		"no auth header": {
			input: http.Header{"Auth": []string{"ApiKey NcvXrl"}},
			wantVal: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"auth header too short": {
			input: http.Header{"Authorization": []string{"ApiKey:NcvXrl"}},
			wantVal: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"wrong apikey name": {
			input: http.Header{"Authorization": []string{"ApiKee NcvXrl"}},
			wantVal: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)
			if !reflect.DeepEqual(tc.wantVal, got) {
				t.Fatalf("expected value: %v, got value: %v", tc.wantVal, got)
			}
			if !reflect.DeepEqual(tc.wantErr, err) {
				t.Fatalf("expected error: %v, got error: %v", tc.wantErr, err)
			}
		})
	}
}
