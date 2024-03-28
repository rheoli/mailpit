// Package spamassassin will return results from either a SpamAssassin server or
// Postmark's public API depending on configuration
package rspamd

import (
	"errors"
	"math"
	"strings"
        "fmt"
        "bytes"

        "net/http"
        "encoding/json"
	"github.com/axllent/mailpit/internal/rspamd/spamc"
)

var (
	// Service to use, either "<host>:<ip>" for self-hosted SpamAssassin or "postmark"
	service string

	// SpamScore is the score at which a message is determined to be spam
	spamScore = 5.0

	// Timeout in seconds
	timeout = 8
)

type rspamd struct {
    Score         float32
    RequiredScore float32 `json:"required_score"`
    Subject       string
    Action        string
    Messages      struct {
       SMTP string `json:"smtp_message"`
    } `json:"messages"`
    DKIMSig interface{} `json:"dkim-signature"`
    Headers struct {
      Remove map[string]int8        `json:"remove_headers"`
      Add    map[string]interface{} `json:"add_headers"`
    } `json:"milter"`
    Symbols map[string]struct {
      Score float32
      Description string
    } `json:"symbols"`
}

// Result is a SpamAssassin result
//
// swagger:model SpamAssassinResponse
type Result struct {
	// Whether the message is spam or not
	IsSpam bool
	// If populated will return an error string
	Error string
	// Total spam score based on triggered rules
	Score float64
	// Spam rules triggered
	Rules []Rule
}

// Rule struct
type Rule struct {
	// Spam rule score
	Score float64
	// SpamAssassin rule name
	Name string
	// SpamAssassin rule description
	Description string
}


// SetService defines which service should be used.
func SetService(s string) {
	service = s
}

// SetTimeout defines the timeout
func SetTimeout(t int) {
	if t > 0 {
		timeout = t
	}
}

// Ping returns whether a service is active or not
func Ping() error {
	if service == "rspamd" {
		return nil
	}

	var client *spamc.Client
	if strings.HasPrefix("unix:", service) {
		client = spamc.NewUnix(strings.TrimLeft(service, "unix:"))
	} else {
		client = spamc.NewTCP(service, timeout)
	}

	return client.Ping()
}

// Check will return a Result
func Check(msg []byte) (Result, error) {

	r := Result{Score: 0}

	if service == "" {
		return r, errors.New("no SpamAssassin service defined")
	}

        var client *http.Client
        var req *http.Request
        var err error

        client = &http.Client{}
        req, err = http.NewRequest("POST", fmt.Sprintf("http://%s/checkv2", service), bytes.NewReader(msg))
        if err != nil {
          return r, errors.New(fmt.Sprintf("rspamd: failed to initialize HTTP request. err: '%s'", err))
        }

        req.Header.Add("Pass", "All")
        req.Header.Add("Ip", "127.0.0.1")
        //req.Header.Add("Hostname", s.rdns)
        //req.Header.Add("Helo", s.heloName)
        //req.Header.Add("MTA-Name", s.mtaName)
        //req.Header.Add("Queue-Id", s.tx.msgid)
        //req.Header.Add("From", s.tx.mailFrom)

        //for _, rcptTo := range s.tx.rcptTo {
        //      req.Header.Add("Rcpt", rcptTo)
        //}

        resp, err := client.Do(req)
        if err != nil {
          return r, errors.New(fmt.Sprintf("rspamd: failed to response from daemon. err: '%s'", err))
        }

        defer resp.Body.Close()

        rr := &rspamd{}
        if err := json.NewDecoder(resp.Body).Decode(rr); err != nil {
          return r, errors.New(fmt.Sprintf("rspamd: failed to decode JSON response. err: '%s'", err))
        }

	r.IsSpam = float64(rr.Score) >= spamScore
	r.Score = round1dm(float64(rr.Score))
	r.Rules = []Rule{}
        if len(rr.Symbols) != 0 {
          for k := range rr.Symbols {
		rule := Rule{}
		rule.Name = k
                rule.Score = round1dm(float64(rr.Symbols[k].Score))
		rule.Description = rr.Symbols[k].Description
		r.Rules = append(r.Rules, rule)
          }
	}

	return r, nil
}

// Round to one decimal place
func round1dm(n float64) float64 {
	return math.Floor(n*10) / 10
}
