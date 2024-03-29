// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

package protolator

import (
	"io"

	plator "github.com/BSNDA/fabric-sdk-go-gm/internal/github.com/hyperledger/fabric/common/tools/protolator"
	"github.com/golang/protobuf/proto"
)

// DeepMarshalJSON marshals msg to w as JSON, but instead of marshaling bytes fields which contain nested
// marshaled messages as base64 (like the standard proto encoding), these nested messages are remarshaled
// as the JSON representation of those messages.  This is done so that the JSON representation is as non-binary
// and human readable as possible.
func DeepMarshalJSON(w io.Writer, msg proto.Message) error {
	return plator.DeepMarshalJSON(w, msg)
}

// DeepUnmarshalJSON takes JSON output as generated by DeepMarshalJSON and decodes it into msg
// This includes re-marshaling the expanded nested elements to binary form
func DeepUnmarshalJSON(r io.Reader, msg proto.Message) error {
	return plator.DeepUnmarshalJSON(r, msg)
}
