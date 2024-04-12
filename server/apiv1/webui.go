package apiv1

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/axllent/mailpit/config"
)

// Response includes global web UI settings
//
// swagger:model WebUIConfiguration
type webUIConfiguration struct {
	// Message Relay information
	MessageRelay struct {
		// Whether message relaying (release) is enabled
		Enabled bool
		// The configured SMTP server address
		SMTPServer string
		// Enforced Return-Path (if set) for relay bounces
		ReturnPath string
		// Only allow relaying to these recipients (regex)
		AllowedRecipients string
		// DEPRECATED 2024/03/12
		// swagger:ignore
		RecipientAllowlist string
	}

	// Whether SpamAssassin is enabled
	SpamAssassin bool

	// Whether SpamAssassin is enabled
	Rspamd bool

	// Whether messages with duplicate IDs are ignored
	DuplicatesIgnored bool
}

// WebUIConfig returns configuration settings for the web UI.
func WebUIConfig(w http.ResponseWriter, _ *http.Request) {
	// swagger:route GET /api/v1/webui application WebUIConfiguration
	//
	// # Get web UI configuration
	//
	// Returns configuration settings for the web UI.
	// Intended for web UI only!
	//
	//	Produces:
	//	- application/json
	//
	//	Schemes: http, https
	//
	//	Responses:
	//		200: WebUIConfigurationResponse
	//		default: ErrorResponse
	conf := webUIConfiguration{}

	conf.MessageRelay.Enabled = config.ReleaseEnabled
	if config.ReleaseEnabled {
		conf.MessageRelay.SMTPServer = fmt.Sprintf("%s:%d", config.SMTPRelayConfig.Host, config.SMTPRelayConfig.Port)
		conf.MessageRelay.ReturnPath = config.SMTPRelayConfig.ReturnPath
		conf.MessageRelay.AllowedRecipients = config.SMTPRelayConfig.AllowedRecipients
		// DEPRECATED 2024/03/12
		conf.MessageRelay.RecipientAllowlist = config.SMTPRelayConfig.AllowedRecipients
	}

	conf.SpamAssassin = config.EnableSpamAssassin != ""
	conf.Rspamd = config.EnableRspamd != ""
	conf.DuplicatesIgnored = config.IgnoreDuplicateIDs

	bytes, _ := json.Marshal(conf)

	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write(bytes)
}
