package vault

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPayloadMarshal(t *testing.T) {
	payload := &Payload{Data: "test"}

	marshaledData, err := payload.Marshal()
	if err != nil {
		t.Errorf("Marshal() returned error: %v", err)
	}

	expectedData, err := json.Marshal(payload)
	if err != nil {
		t.Errorf("json.Marshal() returned error: %v", err)
	}

	if !reflect.DeepEqual(marshaledData, expectedData) {
		t.Errorf("Marshal() returned unexpected data. Expected: %s, Got: %s", expectedData, marshaledData)
	}
}

func TestPayloadUnmarshal(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		testData := `{"d": "test"}`
		expectedPayload := &Payload{Data: "test"}

		payload, err := PayloadUnmarshal([]byte(testData))
		if err != nil {
			t.Errorf("PayloadUnmarshal() returned error: %v", err)
		}

		if !reflect.DeepEqual(payload, expectedPayload) {
			t.Errorf("PayloadUnmarshal() returned unexpected payload. Expected: %v, Got: %v", expectedPayload, payload)
		}
	})

	t.Run("invalid data", func(t *testing.T) {
		testData := `invalid json`

		payload, err := PayloadUnmarshal([]byte(testData))
		if err == nil {
			t.Errorf("PayloadUnmarshal() did not return expected error for invalid JSON data")
		}

		if payload != nil {
			t.Errorf("PayloadUnmarshal() returned unexpected payload for invalid JSON data: %v", payload)
		}
	})

}
