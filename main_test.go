package main

import (
	"errors"
	"fmt"
	"github.com/nijave/certbot-manual-freedns/mocks"
	"github.com/ramalhais/go-freedns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"strings"
	"testing"
)

const ChallengeDomain = "s.example.com"
const ChallengeDomainId = "123456"
const ChallengeValue = "abc123"

func makeMocks() (*DnsChallenge, *mocks.DnsHost, *mocks.TxtResolver) {
	logger, _ := zap.NewDevelopment()

	mockDnsHost := &mocks.DnsHost{}
	mockDnsResolver := &mocks.TxtResolver{}
	challenger := &DnsChallenge{
		ChallengeDomain: ChallengeDomain,
		ChallengeValue:  ChallengeValue,
		Log:             logger.Sugar(),
		Timeout:         0,
		dnsHost:         mockDnsHost,
		resolver:        mockDnsResolver,
		resolveTimeout:  1,
		retryTimeout:    1,
	}

	return challenger, mockDnsHost, mockDnsResolver
}

func TestChallengeRecordIsCreated(t *testing.T) {
	challengeDomainParts := strings.Split(ChallengeDomain, ".")
	require.Equal(t, 3, len(challengeDomainParts))
	rootDomain := challengeDomainParts[1] + "." + challengeDomainParts[2]

	cases := map[string]string{
		rootDomain:      "_acme-challenge." + challengeDomainParts[0],
		ChallengeDomain: "_acme-challenge",
	}

	for domain, subdomain := range cases {
		challenger, mockDnsHost, mockResolver := makeMocks()

		mockDnsHost.On("GetDomains").Return(map[string]string{domain: ChallengeDomainId}, map[string]string{}, nil)
		mockDnsHost.On("GetRecords", mock.Anything).Return(map[string]freedns.Record{}, nil)
		mockDnsHost.On("FindRecordIds", mock.Anything, mock.Anything).Return([]string{}, false)
		// Record created successfully
		mockDnsHost.On("CreateRecord", ChallengeDomainId, subdomain, "TXT", fmt.Sprintf("\"%s\"", ChallengeValue), mock.Anything).Return(nil)
		mockResolver.On("LookupTXT", mock.Anything, subdomain+"."+domain).Return([]string{ChallengeValue}, nil)

		err := challenger.Create()
		assert.NoError(t, err)
	}
}

func TestChallengeRecordZoneMissing(t *testing.T) {
	challenger, mockDnsHost, _ := makeMocks()
	mockDnsHost.On("GetDomains").Return(map[string]string{}, map[string]string{}, nil)
	challenger.Create()
	mockDnsHost.AssertNotCalled(t, "CreateRecord")
}

func TestChallengeRecordRetriesErrors(t *testing.T) {
	for _, firstLookupReturn := range []error{
		errors.New("no such host"),
		errors.New("some random thing"),
	} {
		challenger, mockDnsHost, mockResolver := makeMocks()

		mockDnsHost.On("GetDomains").Return(map[string]string{ChallengeDomain: ChallengeDomainId}, map[string]string{}, nil)
		// No existing records to delete
		mockDnsHost.On("GetRecords", mock.Anything).Return(map[string]freedns.Record{}, nil)
		mockDnsHost.On("FindRecordIds", mock.Anything, mock.Anything).Return([]string{}, false)
		// Record created successfully
		mockDnsHost.On("CreateRecord", ChallengeDomainId, "_acme-challenge", "TXT", fmt.Sprintf("\"%s\"", ChallengeValue), mock.Anything).Return(nil)
		mockResolver.On("LookupTXT", mock.Anything, "_acme-challenge."+ChallengeDomain).Return([]string{}, firstLookupReturn).Once()
		mockResolver.On("LookupTXT", mock.Anything, "_acme-challenge."+ChallengeDomain).Return([]string{ChallengeValue}, nil).Once()

		err := challenger.Create()
		assert.NoError(t, err)
	}
}

func TestCreateDeletesExistingRecord(t *testing.T) {
	challenger, mockDnsHost, _ := makeMocks()

	mockDnsHost.On("GetDomains").Return(map[string]string{ChallengeDomain: ChallengeDomainId}, map[string]string{}, nil)
	mockDnsHost.On("CreateRecord", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New(" You already have another already existent"))

	recordId := "1"
	mockDnsHost.On("GetRecords", mock.Anything).Return(map[string]freedns.Record{recordId: {}}, nil)
	mockDnsHost.On("FindRecordIds", mock.Anything, fmt.Sprintf("_acme-challenge.%s", ChallengeDomain)).Return([]string{recordId}, true)
	mockDnsHost.On("DeleteRecord", recordId).Return(nil)

	challenger.Create()

	mockDnsHost.AssertCalled(t, "DeleteRecord", recordId)
}

//func TestCreateDeletesExistingError(t *testing.T) {
//	for _, returnArguments := range [][][]interface{}{
//		{
//			// No records are found
//			{map[string]freedns.Record{}, nil},
//			{[]string{}, true},
//		},
//		{
//			// An error occurred during record lookup
//			{nil, errors.New("something bad happened")},
//			{},
//		},
//		{
//			// Record couldn't be found in return values
//			{nil, nil},
//			{nil, false},
//		},
//	} {
//		challenger, mockDnsHost, _ := makeMocks()
//
//		mockDnsHost.On("GetDomains").Return(map[string]string{ChallengeDomain: ChallengeDomainId}, map[string]string{}, nil)
//		mockDnsHost.On("CreateRecord", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New(" You already have another already existent"))
//
//		mockDnsHost.On("GetRecords", mock.Anything).Return(returnArguments[0]...)
//		mockDnsHost.On("FindRecordIds", mock.Anything, mock.Anything).Return(returnArguments[1]...)
//
//		challenger.Create()
//
//		mockDnsHost.AssertNotCalled(t, "DeleteRecord")
//	}
//}
