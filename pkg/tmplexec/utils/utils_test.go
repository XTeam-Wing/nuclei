package utils

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestAddExploitStepSyncsResults(t *testing.T) {
	steps := []output.ExploitStep{}
	event := &output.InternalWrappedEvent{
		InternalEvent: output.InternalEvent{
			"request":  "GET /first HTTP/1.1",
			"response": "HTTP/1.1 200 OK",
		},
		Results: []*output.ResultEvent{{TemplateID: "test", Type: "http"}},
	}

	AddExploitStep("first", event, &steps)
	require.Len(t, event.ExploitSteps, 1)
	require.Len(t, event.Results[0].ExploitSteps, 1)
	require.Equal(t, "first", event.Results[0].ExploitSteps[0].StepID)

	event.InternalEvent = output.InternalEvent{
		"request":  "GET /second HTTP/1.1",
		"response": "HTTP/1.1 200 OK",
	}
	AddExploitStep("second", event, &steps)

	require.Len(t, event.ExploitSteps, 2)
	require.Len(t, event.Results[0].ExploitSteps, 2)
	require.Equal(t, "first", event.Results[0].ExploitSteps[0].StepID)
	require.Equal(t, "second", event.Results[0].ExploitSteps[1].StepID)
}

func TestAddExploitStepSkipsEmptyRawData(t *testing.T) {
	steps := []output.ExploitStep{}
	event := &output.InternalWrappedEvent{
		InternalEvent: output.InternalEvent{},
		Results:       []*output.ResultEvent{{TemplateID: "test", Type: "http"}},
	}

	AddExploitStep("empty", event, &steps)
	require.Empty(t, steps)
	require.Empty(t, event.Results[0].ExploitSteps)
}
