package vault

import "encoding/json"

type Payload struct {
	Data string `json:"d"`
}

func (p *Payload) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

func PayloadUnmarshal(data []byte) (*Payload, error) {
	var p = &Payload{}

	err := json.Unmarshal(data, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}
