package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/ramalhais/go-freedns"
	"go.uber.org/zap"
	"net"
	"os"
	"strings"
	"time"
)

const DefaultConfigFile = "/etc/freedns.yaml"
const FreeTtlValue = "For our premium supporters"

type DnsHost interface {
	GetDomains() (map[string]string, map[string]string, error)
	GetRecords(string) (map[string]freedns.Record, error)
	FindRecordIds(map[string]freedns.Record, string) ([]string, bool)
	CreateRecord(string, string, string, string, string) error
	DeleteRecord(string) error
}

type DnsChallenge struct {
	ChallengeDomain string
	ChallengeValue  string
	Log             *zap.SugaredLogger
	LastZoneId      string
	LastRecordName  string
	LastRecordFQDN  string
	dnsHost         DnsHost
	Timeout         time.Duration
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
		if strings.HasSuffix(domain, z) && len(z) > len(zone) {
			zone = z
		}
	}
	return zone
}

func stringStartsWith(str string, prefixes []string) bool {
	str = strings.TrimPrefix(str, " ")
	for _, prefix := range prefixes {
		if strings.HasPrefix(str, prefix) {
			return true
		}
	}
	return false
}

func (c *DnsChallenge) waitForPropagation(ctx context.Context) error {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 2 * time.Second,
			}
			// TODO probably a good idea to try the other resolvers {ns2..ns4} if this one fails
			return d.DialContext(ctx, network, "ns1.afraid.org:53")
		},
	}

	// Seems like this usually takes ~50 seconds
	for i := 0; i < 30; i++ {
		timeout, timeoutCancel := context.WithTimeout(ctx, 3*time.Second)
		records, err := resolver.LookupTXT(timeout, c.LastRecordFQDN)
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
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	return nil
}

func (c *DnsChallenge) Create() error {
	var ctx context.Context
	if c.Timeout > 0 {
		var ctxCancel func()
		ctx, ctxCancel = context.WithTimeout(context.Background(), c.Timeout)
		defer ctxCancel()
	} else {
		ctx = context.Background()
	}

	domains, _, err := c.dnsHost.GetDomains()
	if err != nil {
		return err
	}

	// TODO not sure if these are used correctly...
	if ctx.Err() != nil {
		return ctx.Err()
	}

	zones := make([]string, len(domains))
	for domain, _ := range domains {
		zones = append(zones, domain)
	}

	challengeDomainZone := getZoneFor(zones, c.ChallengeDomain)
	if challengeDomainZone == "" {
		return errors.New("couldn't find zone for domain")
	}
	c.LastZoneId = domains[challengeDomainZone]
	c.Log.Infow("found zone", "zoneName", challengeDomainZone, "zoneId", c.LastZoneId)

	c.LastRecordName = "_acme-challenge." + strings.TrimSuffix(c.ChallengeDomain, "."+challengeDomainZone)
	c.LastRecordFQDN = fmt.Sprintf("%s.%s", c.LastRecordName, challengeDomainZone)
	c.Log.Infow("creating dns challenge", "name", c.LastRecordName, "value", c.ChallengeValue)

	challengeRecord := fmt.Sprintf("\"%s\"", c.ChallengeValue)
	err = c.dnsHost.CreateRecord(c.LastZoneId, c.LastRecordName, "TXT", challengeRecord, FreeTtlValue)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Some retry-able errors. Capacity limit is a free-account edge case where an existing challenge may exist and deleting it frees up enough capacity to recreate it
	if err != nil && stringStartsWith(err.Error(), []string{"You already have another already existent", "You have no more subdomain capacity allocated"}) {
		c.Log.Warn("existing challenge. Deleting and retrying creation")
		deleteErr := c.Delete()
		if deleteErr != nil {
			c.Log.Error(deleteErr)
		}
		// TODO maybe this should wait for the TTL to retry (that'd be an hour though...)
		err = c.dnsHost.CreateRecord(c.LastZoneId, c.LastRecordName, "TXT", challengeRecord, FreeTtlValue)
	}

	if err != nil {
		return err
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// It doesn't seem like certbot will wait around--it will insta-fail if there's NXDOMAIN
	// Try to find the record first before returning to certbot
	err = c.waitForPropagation(ctx)

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
		return errors.New("couldn't find record to delete")
	}
	if len(recordIds) != 1 {
		return errors.New("expected to find a single record")
	}

	return c.dnsHost.DeleteRecord(recordIds[0])
}

func main() {
	logger, err := zap.NewProduction()
	defer logger.Sync()
	if err != nil {
		panic(err)
	}
	sugar := logger.Sugar()

	var configFile string
	flag.StringVar(&configFile, "config-file", "", "path to config file")
	flag.Parse()

	if configFile == "" {
		configFile = DefaultConfigFile
	}

	challengeDomain := requireEnv("CERTBOT_DOMAIN")
	recordValue := requireEnv("CERTBOT_VALIDATION")
	authScriptOutput := os.Getenv("CERTBOT_AUTH_OUTPUT")
	// TODO handle delete/cleanup
	sugar.Infow("auth script output", "output", authScriptOutput)

	freeDnsClient, err := freedns.NewFreeDNS()
	if err != nil {
		panic(err)
	}
	challenger := DnsChallenge{ChallengeDomain: challengeDomain, ChallengeValue: recordValue, Log: sugar, dnsHost: freeDnsClient}
	if authScriptOutput == "" {
		err = challenger.Create()
		if err != nil {
			panic(err)
		}
		os.Stdout.Write([]byte(fmt.Sprintf("%s,%s", challenger.LastZoneId, challenger.LastRecordFQDN)))
		sugar.Info("challenge created")
	} else {
		lastRunInfo := strings.Split(authScriptOutput, ",")
		if len(lastRunInfo) != 2 {
			panic(errors.New("expected CERTBOT_AUTH_OUTPUT to be 2 comma separated values: zoneId,recordName"))
		}
		challenger.LastZoneId = lastRunInfo[0]
		challenger.LastRecordFQDN = lastRunInfo[1]
		err = challenger.Delete()
		if err != nil {
			panic(err)
		}
		sugar.Info("challenge deleted")
	}
}
