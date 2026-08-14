package output

import json "github.com/projectdiscovery/nuclei/v3/pkg/utils/json"

// formatJSON formats the output for json based formatting
func (w *StandardWriter) formatJSON(output *ResultEvent) ([]byte, error) {
	if !w.jsonReqResp { // don't show request-response in json if not asked
		output.Request = ""
		output.Response = ""
		output.ExploitSteps = nil // also omit raw step data when request/response is suppressed
	}
	return json.Marshal(output)
}
