package transport

// JSON Structure for POST Request to /api/generate
type Generate struct {
	Payload           []byte `json:"payload"`
	EncryptionAlgo    string `json:"encrypt"`
	OutputFormat      string `json:"output"`
	OutputName        string `json:"name"`
	ExecutionMethod   string `json:"method"`
	InjectMethod      string `json:"inject"`
	ExecDelay         int    `json:"delay"`
	CheckHostname     bool   `json:"checkHost"`
	CheckDomainJoined bool   `json:"checkDomainJoined"`
	Hostname          string `json:"hostname"`
	DoApiHashing      bool   `json:"doApiHashing"`
	ExportedFunc      string `json:"exportedFunction"`
	Debug             bool   `json:"debug"`
	CheckVm           bool   `json:"checkVm"`
	CheckDebug        bool   `json:"checkDebug"`
	CompanyName       string `json:"company"`
	FileVersion       string `json:"fileVersion"`
	FileDescription   string `json:"fileDescription"`
	ProductName       string `json:"productName"`
	ProductVersion    string `json:"productVersion"`
	OriginalFilename  string `json:"originalFilename"`
	InternalName      string `json:"internalName"`
	Copyright         string `json:"copyright"`
	Icon              string `json:"icon"`
}
