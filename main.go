package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/ramalhais/go-freedns"
	"go.uber.org/zap"
	"net"
	"os"
	"strings"
	"time"
)

// FreeTtlValue Value taken from the FreeDNS website form
const FreeTtlValue = "For our premium supporters"

const DeleteRecordNotFoundMessage = "couldn't find record to delete"

type DnsHost interface {
	GetDomains() (map[string]string, map[string]string, error)
	GetRecords(string) (map[string]freedns.Record, error)
	FindRecordIds(map[string]freedns.Record, string) ([]string, bool)
	CreateRecord(string, string, string, string, string) error
	DeleteRecord(string) error
}

type TxtResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type DnsChallenge struct {
	ChallengeDomain string
	ChallengeValue  string
	Log             *zap.SugaredLogger
	LastZoneId      string
	LastRecordName  string
	LastRecordFQDN  string
	dnsHost         DnsHost
	resolver        TxtResolver
	Timeout         time.Duration
	resolveTimeout  time.Duration
	retryTimeout    time.Duration
	ctx             context.Context
}

func requireEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		panic(errors.New(fmt.Sprintf("environment variable %s is missing", name)))
	}
	return value
}

func getZoneFor(zones []string, domain string) string {
	zone := ""
	for _, z := range zones {
		if strings.HasSuffix(domain, z) && len(z) >= len(zone) {
			zone = z
		}
	}
	return zone
}

func (c *DnsChallenge) setup() error {
	var ctx context.Context
	if c.Timeout > 0 {
		var ctxCancel func()
		ctx, ctxCancel = context.WithTimeout(context.Background(), c.Timeout)
		defer ctxCancel()
	} else {
		ctx = context.Background()
	}
	c.ctx = ctx

	domains, _, err := c.dnsHost.GetDomains()
	if err != nil {
		return err
	}

	// TODO not sure if these are used correctly...
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}

	zones := make([]string, len(domains))
	for domain := range domains {
		zones = append(zones, domain)
	}

	challengeDomainZone := getZoneFor(zones, c.ChallengeDomain)
	if challengeDomainZone == "" {
		return errors.New("couldn't find zone for domain")
	}
	c.LastZoneId = domains[challengeDomainZone]
	c.Log.Infow("found zone", "zoneName", challengeDomainZone, "zoneId", c.LastZoneId)

	c.LastRecordName = "_acme-challenge"
	if challengeDomainZone != c.ChallengeDomain {
		c.LastRecordName += "." + strings.TrimSuffix(c.ChallengeDomain, "."+challengeDomainZone)
	}
	c.LastRecordFQDN = fmt.Sprintf("%s.%s", c.LastRecordName, challengeDomainZone)

	return nil
}

func (c *DnsChallenge) waitForPropagation() error {
	if c.resolver == nil {
		c.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 2 * time.Second,
				}
				// TODO probably a good idea to try the other resolvers {ns2..ns4} if this one fails
				return d.DialContext(ctx, network, "ns1.afraid.org:53")
			},
		}

		if c.resolveTimeout == 0 {
			c.resolveTimeout = 3 * time.Second
		}

		if c.retryTimeout == 0 {
			c.retryTimeout = 10 * time.Second
		}
	}

	// Seems like this usually takes ~50 seconds
	for i := 0; i < 30; i++ {
		timeout, timeoutCancel := context.WithTimeout(c.ctx, c.resolveTimeout)
		records, err := c.resolver.LookupTXT(timeout, c.LastRecordFQDN)
		timeoutCancel()
		if err != nil && strings.HasSuffix(err.Error(), "no such host") {
			c.Log.Warnw("dns record not found", "record", c.LastRecordFQDN, "try", i)
		} else if err != nil {
			c.Log.Error(err)
		} else if len(records) == 1 {
			c.Log.Infow("found txt value", "record", c.LastRecordFQDN, "value", records[0], "try", i)
			if records[0] == c.ChallengeValue {
				return nil
			}
		}

		// https://stackoverflow.com/a/69291047/2751619
		timer := time.NewTimer(c.retryTimeout)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return c.ctx.Err()
		case <-timer.C:
		}
	}

	return errors.New("timed out waiting for txt record")
}

func (c *DnsChallenge) Create() error {
	err := c.setup()
	if err != nil {
		return err
	}

	err = c.Delete()
	if err != nil && err.Error() != DeleteRecordNotFoundMessage {
		return err
	}

	c.Log.Infow("creating dns challenge", "name", c.LastRecordName, "value", c.ChallengeValue)

	challengeRecord := fmt.Sprintf("\"%s\"", c.ChallengeValue)
	err = c.dnsHost.CreateRecord(c.LastZoneId, c.LastRecordName, "TXT", challengeRecord, FreeTtlValue)
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}

	if err != nil {
		return err
	}

	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}

	// It doesn't seem like certbot will wait around--it will insta-fail if there's NXDOMAIN
	// Try to find the record first before returning to certbot
	err = c.waitForPropagation()

	return err
}

func (c *DnsChallenge) Delete() error {
	records, err := c.dnsHost.GetRecords(c.LastZoneId)
	if err != nil {
		return err
	}

	recordIds, ok := c.dnsHost.FindRecordIds(records, c.LastRecordFQDN)
	c.Log.Infow("found records to delete", "recordIds", recordIds)
	if !ok {
		return errors.New(DeleteRecordNotFoundMessage)
	}

	for _, recordId := range recordIds {
		err = c.dnsHost.DeleteRecord(recordId)
		if err != nil {
			return err
		}
	}

	return nil
}

func runChallenger(challengeDomain, recordValue, authScriptOutput string, sugar *zap.SugaredLogger) error {
	freeDnsClient, err := freedns.NewFreeDNS()
	if err != nil {
		return err
	}
	challenger := DnsChallenge{ChallengeDomain: challengeDomain, ChallengeValue: recordValue, Log: sugar, dnsHost: freeDnsClient}
	if authScriptOutput == "" {
		err = challenger.Create()
		if err != nil {
			return err
		}
		os.Stdout.Write([]byte(fmt.Sprintf("%s,%s", challenger.LastZoneId, challenger.LastRecordFQDN)))
		sugar.Info("challenge created")
	} else {
		lastRunInfo := strings.Split(authScriptOutput, ",")
		if len(lastRunInfo) != 2 {
			return errors.New("expected CERTBOT_AUTH_OUTPUT to be 2 comma separated values: zoneId,recordName")
		}
		challenger.LastZoneId = lastRunInfo[0]
		challenger.LastRecordFQDN = lastRunInfo[1]
		err = challenger.Delete()
		if err != nil {
			return err
		}
		sugar.Info("challenge deleted")
	}

	return nil
}

func main() {
	logger, err := zap.NewProduction()
	defer logger.Sync()
	if err != nil {
		panic(err)
	}
	sugar := logger.Sugar()

	challengeDomain := requireEnv("CERTBOT_DOMAIN")
	recordValue := requireEnv("CERTBOT_VALIDATION")
	authScriptOutput := os.Getenv("CERTBOT_AUTH_OUTPUT")
	// TODO handle delete/cleanup
	sugar.Infow("auth script output", "output", authScriptOutput)

	err = runChallenger(challengeDomain, recordValue, authScriptOutput, sugar)
	if err != nil {
		panic(err)
	}
}
