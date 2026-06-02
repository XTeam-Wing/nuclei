package utils

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// FillPreviousEvent is a helper function to get the previous event from the event
// without leading to duplicate prefixes
func FillPreviousEvent(reqID string, event *output.InternalWrappedEvent, previous *mapsutil.SyncLockMap[string, any]) {
	if reqID == "" {
		return
	}

	for k, v := range event.InternalEvent {
		if _, ok := previous.Get(k); ok {
			continue
		}

		if strings.HasPrefix(k, reqID+"_") {
			continue
		}

		var builder strings.Builder

		builder.WriteString(reqID)
		builder.WriteString("_")
		builder.WriteString(k)

		_ = previous.Set(builder.String(), v)
	}
}

// AddExploitStep records the current request/response and keeps generated results in sync.
func AddExploitStep(reqID string, event *output.InternalWrappedEvent, steps *[]output.ExploitStep) {
	if event == nil || event.InternalEvent == nil {
		return
	}

	request := types.ToString(event.InternalEvent["request"])
	response := types.ToString(event.InternalEvent["response"])
	if request == "" && response == "" {
		return
	}

	*steps = append(*steps, output.ExploitStep{
		StepNumber: len(*steps) + 1,
		StepID:     reqID,
		Request:    request,
		Response:   response,
	})
	AttachExploitSteps(event, *steps)
}

// AttachExploitSteps copies the chain onto the wrapped event and its result events.
func AttachExploitSteps(event *output.InternalWrappedEvent, steps []output.ExploitStep) {
	if event == nil || len(steps) < 2 {
		return
	}

	stepsCopy := make([]output.ExploitStep, len(steps))
	copy(stepsCopy, steps)
	event.ExploitSteps = stepsCopy

	for _, result := range event.Results {
		result.ExploitSteps = stepsCopy
	}
}
