/**
 * @Author: Gao Chenxi
 * @Description:
 * @File:  txnhandle_bsn_select
 * @Version: 1.0.0
 * @Date: 2020/4/8 15:39
 */

package invoke

import (
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/providers/fab"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/fab/peer"
	"github.com/pkg/errors"
)

type BsnSelectAndEndorseHandler struct {
	*BsnEndorsementHandler
	next Handler
}

// NewSelectAndEndorseHandler returns a new SelectAndEndorseHandler
func NewBsnSelectAndEndorseHandler(next ...Handler) Handler {
	return &BsnSelectAndEndorseHandler{
		BsnEndorsementHandler: NewBsnEndorsementHandler(),
		next:                  getNext(next),
	}
}

// Handle selects endorsers and sends proposals to the endorsers
func (e *BsnSelectAndEndorseHandler) Handle(requestContext *RequestContext, clientContext *ClientContext) {
	//GatewayLog.Logs("SelectAndEndorseHandler Handle")
	var ccCalls []*fab.ChaincodeCall
	targets := requestContext.Opts.Targets
	if len(targets) == 0 {
		var err error
		ccCalls, requestContext.Opts.Targets, err = getEndorsers(requestContext, clientContext)
		if err != nil {
			requestContext.Error = err
			return
		}
	}
	//GatewayLog.Logs("SelectAndEndorseHandler =》 EndorsementHandler Handle")
	e.BsnEndorsementHandler.Handle(requestContext, clientContext)
	//GatewayLog.Logs("SelectAndEndorseHandler =》 EndorsementHandler Handle End")
	if requestContext.Error != nil {
		return
	}

	if len(targets) == 0 && len(requestContext.Response.Responses) > 0 {
		additionalEndorsers, err := getAdditionalEndorsers(requestContext, clientContext, ccCalls)
		if err != nil {
			// Log a warning. No need to fail the endorsement. Use the responses collected so far,
			// which may be sufficient to satisfy the chaincode policy.
			logger.Warnf("error getting additional endorsers: %s", err)
		} else {
			if len(additionalEndorsers) > 0 {
				requestContext.Opts.Targets = additionalEndorsers
				logger.Debugf("...getting additional endorsements from %d target(s)", len(additionalEndorsers))
				additionalResponses, err := clientContext.Transactor.SendTransactionProposal(requestContext.Response.Proposal, peer.PeersToTxnProcessors(additionalEndorsers))
				if err != nil {
					requestContext.Error = errors.WithMessage(err, "error sending transaction proposal")
					return
				}

				// Add the new endorsements to the list of responses
				requestContext.Response.Responses = append(requestContext.Response.Responses, additionalResponses...)
			} else {
				logger.Debugf("...no additional endorsements are required.")
			}
		}
	}

	if e.next != nil {
		e.next.Handle(requestContext, clientContext)
	}
}
