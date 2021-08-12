/**
 * @Author: Gao Chenxi
 * @Description:
 * @File:  transactor_bsn
 * @Version: 1.0.0
 * @Date: 2020/4/8 15:23
 */

package channel

import (
	"github.com/pkg/errors"

	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/providers/fab"
	contextImpl "github.com/BSNDA/fabric-sdk-go-gm/pkg/context"

	"github.com/BSNDA/fabric-sdk-go-gm/pkg/fab/txn"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

// SendTransactionProposal sends a TransactionProposal to the target peers.
func (t *Transactor) SendBsnTransactionProposal(proposal *pb.SignedProposal, targets []fab.ProposalProcessor) ([]*fab.TransactionProposalResponse, error) {
	//GatewayLog.Logs("SendTransactionProposal 发送交易给 Peer")
	ctx, ok := contextImpl.RequestClientContext(t.reqCtx)
	if !ok {
		return nil, errors.New("failed get client context from reqContext for SendTransactionProposal")
	}

	reqCtx, cancel := contextImpl.NewRequest(ctx, contextImpl.WithTimeoutType(fab.PeerResponse), contextImpl.WithParent(t.reqCtx))
	defer cancel()

	return txn.SendBsnProposal(reqCtx, proposal, targets)
}

// SendTransaction send a transaction to the chain’s orderer service (one or more orderer endpoints) for consensus and committing to the ledger.
func (t *Transactor) SendBsnTransaction(tx *fab.Transaction) (*fab.TransactionResponse, error) {
	//GatewayLog.Logs("SendTransaction 发送交易 给 Orderer")
	ctx, ok := contextImpl.RequestClientContext(t.reqCtx)
	if !ok {
		return nil, errors.New("failed get client context from reqContext for SendTransaction")
	}

	reqCtx, cancel := contextImpl.NewRequest(ctx, contextImpl.WithTimeoutType(fab.OrdererResponse), contextImpl.WithParent(t.reqCtx))
	defer cancel()

	return txn.BsnSend(reqCtx, tx, t.orderers)
}
