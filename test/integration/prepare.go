/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"fmt"
	"time"

	"github.com/BSNDA/fabric-sdk-go-gm/pkg/client/channel"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/client/resmgmt"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/errors/retry"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/errors/status"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/fab"
	packager "github.com/BSNDA/fabric-sdk-go-gm/pkg/fab/ccpackager/gopackager"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/fab/comm"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/fabsdk"
	"github.com/BSNDA/fabric-sdk-go-gm/test/metadata"
	cb "github.com/hyperledger/fabric-protos-go/common"
	"github.com/pkg/errors"
)

var orgExpectedPeers = map[string]int{
	"Org1": 2,
	"Org2": 2,
}

const (
	defaultChannelID    = "mychannel"
	exampleCCName       = "example_cc"
	exampleCCPath       = "github.com/example_cc"
	exampleCCVersion    = "v0"
	examplePvtCCName    = "example_pvt_cc"
	examplePvtCCPath    = "github.com/example_pvt_cc"
	examplePvtCCVersion = "v0"
	exampleUpgdPvtCCVer = "v1"
)

// GenerateExamplePvtID supplies a chaincode name for example_pvt_cc
func GenerateExamplePvtID(randomize bool) string {
	suffix := "0"
	if randomize {
		suffix = GenerateRandomID()
	}

	return fmt.Sprintf("%s_%s%s", examplePvtCCName, metadata.TestRunID, suffix)
}

// GenerateExampleID supplies a chaincode name for example_cc
func GenerateExampleID(randomize bool) string {
	suffix := "0"
	if randomize {
		suffix = GenerateRandomID()
	}

	return fmt.Sprintf("%s_0%s%s", exampleCCName, metadata.TestRunID, suffix)
}

// PrepareExampleCC install and instantiate using resource management client
func PrepareExampleCC(sdk *fabsdk.FabricSDK, user fabsdk.ContextOption, orgName string, chaincodeID string) error {
	const (
		channelID = defaultChannelID
	)

	instantiated, err := queryInstantiatedCCWithSDK(sdk, user, orgName, channelID, chaincodeID, exampleCCVersion, false)
	if err != nil {
		return errors.WithMessage(err, "Querying for instantiated status failed")
	}

	if instantiated {
		resetErr := resetExampleCC(sdk, user, orgName, channelID, chaincodeID, resetArgs)
		if resetErr != nil {
			return errors.WithMessage(resetErr, "Resetting example chaincode failed")
		}
		return nil
	}

	fmt.Printf("Installing and instantiating example chaincode...")
	start := time.Now()

	ccPolicy, err := prepareOneOrgPolicy(sdk, orgName)
	if err != nil {
		return errors.WithMessage(err, "CC policy could not be prepared")
	}

	orgContexts, err := prepareOrgContexts(sdk, user, []string{orgName})
	if err != nil {
		return errors.WithMessage(err, "Org contexts could not be prepared")
	}

	err = InstallExampleChaincode(orgContexts, chaincodeID)
	if err != nil {
		return errors.WithMessage(err, "Installing example chaincode failed")
	}

	err = InstantiateExampleChaincode(orgContexts, channelID, chaincodeID, ccPolicy)
	if err != nil {
		return errors.WithMessage(err, "Instantiating example chaincode failed")
	}

	t := time.Now()
	elapsed := t.Sub(start)
	fmt.Printf("Done [%d ms]\n", elapsed/time.Millisecond)

	return nil
}

// InstallExampleChaincode installs the example chaincode to all peers in the given orgs
func InstallExampleChaincode(orgs []*OrgContext, ccID string) error {
	ccPkg, err := packager.NewCCPackage(exampleCCPath, GetDeployPath())
	if err != nil {
		return errors.WithMessage(err, "creating chaincode package failed")
	}

	err = InstallChaincodeWithOrgContexts(orgs, ccPkg, exampleCCPath, ccID, exampleCCVersion)
	if err != nil {
		return errors.WithMessage(err, "installing example chaincode failed")
	}

	return nil
}

// InstallExamplePvtChaincode installs the example pvt chaincode to all peers in the given orgs
func InstallExamplePvtChaincode(orgs []*OrgContext, ccID string) error {
	ccPkg, err := packager.NewCCPackage(examplePvtCCPath, GetDeployPath())
	if err != nil {
		return errors.WithMessage(err, "creating chaincode package failed")
	}

	err = InstallChaincodeWithOrgContexts(orgs, ccPkg, examplePvtCCPath, ccID, examplePvtCCVersion)
	if err != nil {
		return errors.WithMessage(err, "installing example chaincode failed")
	}

	return nil
}

// InstantiateExampleChaincode instantiates the example CC on the given channel
func InstantiateExampleChaincode(orgs []*OrgContext, channelID, ccID, ccPolicy string, collConfigs ...*cb.CollectionConfig) error {
	_, err := InstantiateChaincode(orgs[0].ResMgmt, channelID, ccID, exampleCCPath, exampleCCVersion, ccPolicy, ExampleCCInitArgs(), collConfigs...)
	return err
}

// InstantiateExamplePvtChaincode instantiates the example pvt CC on the given channel
func InstantiateExamplePvtChaincode(orgs []*OrgContext, channelID, ccID, ccPolicy string, collConfigs ...*cb.CollectionConfig) error {
	_, err := InstantiateChaincode(orgs[0].ResMgmt, channelID, ccID, examplePvtCCPath, examplePvtCCVersion, ccPolicy, ExampleCCInitArgs(), collConfigs...)
	return err
}

// UpgradeExamplePvtChaincode upgrades the instantiated example pvt CC on the given channel
func UpgradeExamplePvtChaincode(orgs []*OrgContext, channelID, ccID, ccPolicy string, collConfigs ...*cb.CollectionConfig) error {
	// first install the CC with the upgraded cc version
	ccPkg, err := packager.NewCCPackage(examplePvtCCPath, GetDeployPath())
	if err != nil {
		return errors.WithMessage(err, "creating chaincode package failed")
	}
	err = InstallChaincodeWithOrgContexts(orgs, ccPkg, examplePvtCCPath, ccID, exampleUpgdPvtCCVer)
	if err != nil {
		return errors.WithMessage(err, "installing example chaincode failed")
	}

	// now upgrade cc
	_, err = UpgradeChaincode(orgs[0].ResMgmt, channelID, ccID, examplePvtCCPath, exampleUpgdPvtCCVer, ccPolicy, ExampleCCInitArgs(), collConfigs...)
	return err
}

func resetExampleCC(sdk *fabsdk.FabricSDK, user fabsdk.ContextOption, orgName string, channelID string, chainCodeID string, args [][]byte) error {
	clientContext := sdk.ChannelContext(channelID, user, fabsdk.WithOrg(orgName))

	client, err := channel.New(clientContext)
	if err != nil {
		return errors.WithMessage(err, "Creating channel client failed")
	}

	req := channel.Request{
		ChaincodeID: chainCodeID,
		Fcn:         "reset",
		Args:        args,
	}

	_, err = client.Execute(req, channel.WithRetry(retry.DefaultChannelOpts))
	if err != nil {
		return errors.WithMessage(err, "Reset invocation failed")
	}

	return nil
}

func prepareOrgContexts(sdk *fabsdk.FabricSDK, user fabsdk.ContextOption, orgNames []string) ([]*OrgContext, error) {
	orgContexts := make([]*OrgContext, len(orgNames))

	for i, orgName := range orgNames {
		clientContext := sdk.Context(user, fabsdk.WithOrg(orgName))

		resMgmt, err := resmgmt.New(clientContext)
		if err != nil {
			return nil, errors.WithMessage(err, "Creating resource management client failed")
		}

		expectedPeers, ok := orgExpectedPeers[orgName]
		if !ok {
			return nil, errors.WithMessage(err, "unknown org name")
		}
		peers, err := DiscoverLocalPeers(clientContext, expectedPeers)
		if err != nil {
			return nil, errors.WithMessage(err, "local peers could not be determined")
		}

		orgCtx := OrgContext{
			OrgID:       orgName,
			CtxProvider: clientContext,
			ResMgmt:     resMgmt,
			Peers:       peers,
		}
		orgContexts[i] = &orgCtx
	}
	return orgContexts, nil
}

func prepareOneOrgPolicy(sdk *fabsdk.FabricSDK, orgName string) (string, error) {
	mspID, err := orgMSPID(sdk, orgName)
	if err != nil {
		return "", errors.WithMessage(err, "MSP ID could not be determined")
	}

	return fmt.Sprintf("AND('%s.member')", mspID), nil
}

func orgMSPID(sdk *fabsdk.FabricSDK, orgName string) (string, error) {
	configBackend, err := sdk.Config()
	if err != nil {
		return "", errors.WithMessage(err, "failed to get config backend")
	}

	endpointConfig, err := fab.ConfigFromBackend(configBackend)
	if err != nil {
		return "", errors.WithMessage(err, "failed to get endpoint config")
	}

	mspID, ok := comm.MSPID(endpointConfig, orgName)
	if !ok {
		return "", errors.New("looking up MSP ID failed")
	}

	return mspID, nil
}

func queryInstantiatedCCWithSDK(sdk *fabsdk.FabricSDK, user fabsdk.ContextOption, orgName string, channelID, ccName, ccVersion string, transientRetry bool) (bool, error) {
	clientContext := sdk.Context(user, fabsdk.WithOrg(orgName))

	resMgmt, err := resmgmt.New(clientContext)
	if err != nil {
		return false, errors.WithMessage(err, "Creating resource management client failed")
	}

	return queryInstantiatedCC(resMgmt, orgName, channelID, ccName, ccVersion, transientRetry)
}

func queryInstantiatedCC(resMgmt *resmgmt.Client, orgName string, channelID, ccName, ccVersion string, transientRetry bool) (bool, error) {

	instantiated, err := retry.NewInvoker(retry.New(retry.TestRetryOpts)).Invoke(
		func() (interface{}, error) {
			ok, err := isCCInstantiated(resMgmt, channelID, ccName, ccVersion)
			if err != nil {
				return &ok, err
			}
			if !ok && transientRetry {
				return &ok, status.New(status.TestStatus, status.GenericTransient.ToInt32(), fmt.Sprintf("Did NOT find instantiated chaincode [%s:%s] on one or more peers in [%s].", ccName, ccVersion, orgName), nil)
			}
			return &ok, nil
		},
	)

	if err != nil {
		s, ok := status.FromError(err)
		if ok && s.Code == status.GenericTransient.ToInt32() {
			return false, nil
		}
		return false, errors.WithMessage(err, "isCCInstantiated invocation failed")
	}

	return *instantiated.(*bool), nil
}

func isCCInstantiated(resMgmt *resmgmt.Client, channelID, ccName, ccVersion string) (bool, error) {
	chaincodeQueryResponse, err := resMgmt.QueryInstantiatedChaincodes(channelID, resmgmt.WithRetry(retry.DefaultResMgmtOpts))
	if err != nil {
		return false, errors.WithMessage(err, "Query for instantiated chaincodes failed")
	}

	for _, chaincode := range chaincodeQueryResponse.Chaincodes {
		if chaincode.Name == ccName && chaincode.Version == ccVersion {
			return true, nil
		}
	}
	return false, nil
}
