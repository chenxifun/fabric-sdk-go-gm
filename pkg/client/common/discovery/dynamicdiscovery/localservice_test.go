// +build testing

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dynamicdiscovery

import (
	"errors"
	"testing"
	"time"

	clientmocks "github.com/BSNDA/fabric-sdk-go-gm/pkg/client/common/mocks"
	contextAPI "github.com/BSNDA/fabric-sdk-go-gm/pkg/common/providers/context"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/providers/fab"
	pfab "github.com/BSNDA/fabric-sdk-go-gm/pkg/common/providers/fab"
	discmocks "github.com/BSNDA/fabric-sdk-go-gm/pkg/fab/discovery/mocks"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/fab/mocks"
	mspmocks "github.com/BSNDA/fabric-sdk-go-gm/pkg/msp/test/mockmsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	peer2MSP1 = "peer2.org1.com:9999"
)

func TestLocalDiscoveryService(t *testing.T) {
	ctx := mocks.NewMockContext(mspmocks.NewMockSigningIdentity("test", mspID1))
	config := &mocks.MockConfig{}
	ctx.SetEndpointConfig(config)

	localCtx := mocks.NewMockLocalContext(ctx, nil)

	peer1 := pfab.NetworkPeer{
		PeerConfig: pfab.PeerConfig{
			URL: peer1MSP1,
		},
		MSPID: mspID1,
	}
	config.SetCustomNetworkPeerCfg([]pfab.NetworkPeer{peer1})

	discClient := clientmocks.NewMockDiscoveryClient()
	discClient.SetResponses(
		&clientmocks.MockDiscoverEndpointResponse{
			PeerEndpoints: []*discmocks.MockDiscoveryPeerEndpoint{},
		},
	)

	SetClientProvider(func(ctx contextAPI.Client) (DiscoveryClient, error) {
		return discClient, nil
	})

	// Test initialize with invalid MSP ID
	service := newLocalService(config, mspID2)
	err := service.Initialize(localCtx)
	assert.Error(t, err)

	service = newLocalService(
		config, mspID1,
		WithRefreshInterval(3*time.Millisecond),
		WithResponseTimeout(2*time.Second),
		WithErrorHandler(
			func(ctxt fab.ClientContext, channelID string, err error) {
				derr, ok := err.(DiscoveryError)
				if ok && derr.Error() == AccessDenied {
					service.Close()
				}
			},
		),
	)
	defer service.Close()

	err = service.Initialize(localCtx)
	assert.NoError(t, err)
	// Initialize again should produce no error
	err = service.Initialize(localCtx)
	assert.NoError(t, err)

	peers, err := service.GetPeers()
	assert.NoError(t, err)
	assert.Equal(t, 0, len(peers))

	discClient.SetResponses(
		&clientmocks.MockDiscoverEndpointResponse{
			PeerEndpoints: []*discmocks.MockDiscoveryPeerEndpoint{
				{
					MSPID:        mspID1,
					Endpoint:     peer1MSP1,
					LedgerHeight: 5,
				},
			},
		},
	)

	time.Sleep(time.Second)

	peers, err = service.GetPeers()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(peers), "Expecting 1 peer")

	discClient.SetResponses(
		&clientmocks.MockDiscoverEndpointResponse{
			PeerEndpoints: []*discmocks.MockDiscoveryPeerEndpoint{
				{
					MSPID:        mspID1,
					Endpoint:     peer1MSP1,
					LedgerHeight: 5,
				},
				{
					MSPID:        mspID1,
					Endpoint:     peer2MSP1,
					LedgerHeight: 5,
				},
				{
					MSPID:        mspID2,
					Endpoint:     peer1MSP2,
					LedgerHeight: 5,
				},
			},
		},
	)

	time.Sleep(time.Second)

	peers, err = service.GetPeers()
	assert.NoError(t, err)
	assert.Equal(t, 2, len(peers), "Expecting 2 peers")

	for _, p := range peers {
		assert.Equalf(t, mspID1, p.MSPID(), "Expecting peer to be in MSP [%s]", mspID1)
	}

	// Fatal error (access denied can be due due a user being revoked)
	discClient.SetResponses(
		&clientmocks.MockDiscoverEndpointResponse{
			Error: errors.New(AccessDenied),
		},
	)

	// Wait for the cache to refresh
	time.Sleep(10 * time.Millisecond)

	// The discovery service should have been closed
	_, err = service.GetPeers()
	require.Error(t, err)
	assert.Equal(t, "Discovery client has been closed", err.Error())
}