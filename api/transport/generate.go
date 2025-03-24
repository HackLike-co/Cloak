package transport

// JSON Structure for POST Request to /api/generate
type Generate struct {
	Payload         []byte `json:"payload"`
	EncryptionAlgo  string `json:"encrypt"`
	OutputFormat    string `json:"output"`
	ExecutionMethod string `json:"method"`
	InjectMethod    string `json:"inject"`
	ExecDelay       int    `json:"delay"`
	CheckHostname   bool   `json:"checkHost"`
	Hostname        string `json:"hostname"`
	Debug           bool   `json:"debug"`
}
