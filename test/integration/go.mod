// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/BSNDA/fabric-sdk-go-gm/test/integration

replace github.com/BSNDA/fabric-sdk-go-gm => ../../

require (
	github.com/BSNDA/fabric-sdk-go-gm v0.0.0-00010101000000-000000000000
	github.com/golang/protobuf v1.4.3
	github.com/hyperledger/fabric-protos-go v0.0.0-20200124220212-e9cfc186ba7b
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	google.golang.org/grpc v1.31.0
)

go 1.13
