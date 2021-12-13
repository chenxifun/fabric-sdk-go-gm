/**
 * @Author: Gao Chenxi
 * @Description:
 * @File:  txhandler_bsn
 * @Version: 1.0.0
 * @Date: 2020/4/8 15:13
 */

package invoke

import (
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/errors/status"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/providers/fab"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/fab/peer"

	"github.com/pkg/errors"
)

func NewEndorsementHandlerHasOpts(opts TxnHeaderOptsProvider, next ...Handler) *EndorsementHandler {
	return &EndorsementHandler{next: getNext(next), headerOptsProvider: opts}
}

func NewBsnQueryHandlerHasOpts(opts TxnHeaderOptsProvider, next ...Handler) Handler {
	return NewProposalProcessorHandler(
		NewEndorsementHandlerHasOpts(opts,

			NewEndorsementValidationHandler(
				NewSignatureValidationHandler(next...),
			),
		),
	)
}

func NewBsnExecuteHandlerHasOpts(opts TxnHeaderOptsProvider, next ...Handler) Handler {
	return NewBsnSelectAndEndorseHandlerHasOpts(opts,
		NewEndorsementValidationHandler(
			NewSignatureValidationHandler(NewBsnCommitHandler(next...)),
		),
	)
}

func NewBsnSelectAndEndorseHandlerHasOpts(opts TxnHeaderOptsProvider, next ...Handler) Handler {
	return &SelectAndEndorseHandler{
		EndorsementHandler: NewEndorsementHandlerHasOpts(opts),
		next:               getNext(next),
	}
}

func NewBsnQueryHandler(next ...Handler) Handler {
	return NewProposalProcessorHandler(
		NewBsnEndorsementHandler(
			NewEndorsementValidationHandler(
				NewSignatureValidationHandler(next...),
			),
		),
	)
}

func NewBsnExecuteHandler(next ...Handler) Handler {
	return NewBsnSelectAndEndorseHandler(
		NewEndorsementValidationHandler(
			NewSignatureValidationHandler(NewBsnCommitHandler(next...)),
		),
	)
}

func NewBsnEndorsementHandler(next ...Handler) *BsnEndorsementHandler {
	return &BsnEndorsementHandler{next: getNext(next)}
}

//EndorsementHandler for handling endorse transactions
type BsnEndorsementHandler struct {
	next               Handler
	headerOptsProvider TxnHeaderOptsProvider
}

//Handle for endorsing transactions
func (e *BsnEndorsementHandler) Handle(requestContext *RequestContext, clientContext *ClientContext) {
	//GatewayLog.Logs("BSNEndorsementHandler Handle 开始交易提案")
	if len(requestContext.Opts.Targets) == 0 {
		requestContext.Error = status.New(status.ClientStatus, status.NoPeersFound.ToInt32(), "targets were not provided", nil)
		return
	}

	// Endorse Tx
	var TxnHeaderOpts []fab.TxnHeaderOpt
	if e.headerOptsProvider != nil {
		TxnHeaderOpts = e.headerOptsProvider()
	}
	//GatewayLog.Logs("createAndSendTransactionProposal 开始发送交易提案")

	transactionProposalResponses, proposal, err := createAndSendBsnTransactionProposal(
		clientContext.Transactor,
		&requestContext.Request,
		peer.PeersToTxnProcessors(requestContext.Opts.Targets),
		TxnHeaderOpts...,
	)
	//GatewayLog.Logs("Query createAndSendTransactionProposal END")
	requestContext.Response.Proposal = proposal
	requestContext.Response.TransactionID = proposal.TxnID // TODO: still needed?

	if err != nil {
		requestContext.Error = err
		return
	}

	requestContext.Response.Responses = transactionProposalResponses
	if len(transactionProposalResponses) > 0 {
		requestContext.Response.Payload = transactionProposalResponses[0].ProposalResponse.GetResponse().Payload
		requestContext.Response.ChaincodeStatus = transactionProposalResponses[0].ChaincodeStatus
	}
	//GatewayLog.Logs("Query EndorsementHandler Handle  END")
	//Delegate to next step if any
	if e.next != nil {
		e.next.Handle(requestContext, clientContext)
	}
}

func createAndSendBsnTransactionProposal(transactor fab.ProposalSender, chrequest *Request, targets []fab.ProposalProcessor, opts ...fab.TxnHeaderOpt) ([]*fab.TransactionProposalResponse, *fab.TransactionProposal, error) {

	proposal := chrequest.BsnProposal.TransactionProposal
	signproposal := chrequest.BsnProposal.SignProposal

	//GatewayLog.Logs("SendTransactionProposal 发送交易提案")
	transactionProposalResponses, err := transactor.SendBsnTransactionProposal(signproposal, targets)
	//GatewayLog.Logs("SendTransactionProposal END")
	return transactionProposalResponses, proposal, err
}

//NewCommitHandler returns a handler that commits transaction propsal responses
func NewBsnCommitHandler(next ...Handler) *BsnCommitTxHandler {
	return &BsnCommitTxHandler{next: getNext(next)}
}

//CommitTxHandler for committing transactions
type BsnCommitTxHandler struct {
	next Handler
}

//Handle handles commit tx
func (c *BsnCommitTxHandler) Handle(requestContext *RequestContext, clientContext *ClientContext) {
	//txnID := requestContext.Response.TransactionID
	//GatewayLog.Logs("CommitTxHandler Handle TXID 发送交易", txnID)
	//Register Tx event

	//reg, statusNotifier, err := clientContext.EventService.RegisterTxStatusEvent(string(txnID)) // TODO: Change func to use TransactionID instead of string
	//if err != nil {
	//	requestContext.Error = errors.Wrap(err, "error registering for TxStatus event")
	//	return
	//}
	//defer clientContext.EventService.Unregister(reg)

	res, err := createAndSendBsnTransaction(clientContext.Transactor, requestContext.Response.Proposal, requestContext.Response.Responses)

	//GatewayLog.Logs("CommitTxHandler Handle 交易结束")
	if err != nil {
		requestContext.Error = errors.Wrap(err, "CreateAndSendTransaction failed")
		return
	}
	//requestContext.Response.TxValidationCode = 0
	//GatewayLog.Logs("requestContext.Response.Payload :", string(requestContext.Response.Payload))
	//GatewayLog.Logs("requestContext.Response.BlockNumber :", string(requestContext.Response.BlockNumber))
	//GatewayLog.Logs("requestContext.Response.ChaincodeStatus :", string(requestContext.Response.ChaincodeStatus))
	//select {
	//case txStatus := <-statusNotifier:
	//	//GatewayLog.Logs("statusNotifier 结果接收 ",&txStatus)
	//	requestContext.Response.TxValidationCode = txStatus.TxValidationCode
	//	requestContext.Response.BlockNumber=txStatus.BlockNumber
	//	if txStatus.TxValidationCode != pb.TxValidationCode_VALID {
	//		requestContext.Error = status.New(status.EventServerStatus, int32(txStatus.TxValidationCode),
	//			"received invalid transaction", nil)
	//		return
	//	}
	//case <-requestContext.Ctx.Done():
	//	requestContext.Error = status.New(status.ClientStatus, status.Timeout.ToInt32(),
	//		"Execute didn't receive block event", nil)
	//	return
	//}

	//Delegate to next step if any
	if res != nil {
		requestContext.Response.OrderDataLen = res.DataLen
	}

	if c.next != nil {
		c.next.Handle(requestContext, clientContext)
	}
}

func createAndSendBsnTransaction(sender fab.Sender, proposal *fab.TransactionProposal, resps []*fab.TransactionProposalResponse) (*fab.TransactionResponse, error) {
	//GatewayLog.Logs("createAndSendTransaction 交易处理")
	txnRequest := fab.TransactionRequest{
		Proposal:          proposal,
		ProposalResponses: resps,
	}
	//GatewayLog.Logs("CreateTransaction 创建交易开始")
	tx, err := sender.CreateTransaction(txnRequest)
	//GatewayLog.Logs("CreateTransaction 创建交易结束")
	if err != nil {
		return nil, errors.WithMessage(err, "CreateTransaction failed")
	}
	//GatewayLog.Logs("SendTransaction 发送交易开始")
	transactionResponse, err := sender.SendBsnTransaction(tx)
	//GatewayLog.Logs("SendTransaction 发送交易结束")
	if err != nil {
		return nil, errors.WithMessage(err, "SendTransaction failed")

	}

	return transactionResponse, nil
}
