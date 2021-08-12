// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/BSNDA/fabric-sdk-go-gm/test/performance

replace github.com/BSNDA/fabric-sdk-go-gm => github.com/chenxifun/fabric-sdk-go-gm v1.4.3-bsn-0.2

require (
	github.com/golang/protobuf v1.3.2
	github.com/hyperledger/fabric-protos-go v0.0.0-20190823190507-26c33c998676
	github.com/BSNDA/fabric-sdk-go-gm v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.3.0
	golang.org/x/net v0.0.0-20190311183353-d8887717615a
	google.golang.org/grpc v1.23.0
)

go 1.13
