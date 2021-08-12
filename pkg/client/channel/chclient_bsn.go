/**
 * @Author: Gao Chenxi
 * @Description:
 * @File:  chclient_bsn
 * @Version: 1.0.0
 * @Date: 2020/4/8 14:44
 */

package channel

import (
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/client/channel/invoke"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/client/common/filter"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/providers/fab"
)

func (cc *Client) BsnExecute(request Request, options ...RequestOption) (Response, error) {
	options = append(options, addDefaultTimeout(fab.Execute))
	options = append(options, addDefaultTargetFilter(cc.context, filter.EndorsingPeer))

	return callBsnExecute(cc, request, options...)
}

func (cc *Client) BsnQuery(request Request, options ...RequestOption) (Response, error) {

	options = append(options, addDefaultTimeout(fab.Query))
	options = append(options, addDefaultTargetFilter(cc.context, filter.ChaincodeQuery))

	return callBsnQuery(cc, request, options...)
}

func (cc *Client) BsnExecuteHasOpts(request Request, opts invoke.TxnHeaderOptsProvider, options ...RequestOption) (Response, error) {
	options = append(options, addDefaultTimeout(fab.Execute))
	options = append(options, addDefaultTargetFilter(cc.context, filter.EndorsingPeer))

	return callBsnExecuteHasOpts(cc, request, opts, options...)
}

func (cc *Client) BsnQueryHasOpts(request Request, opts invoke.TxnHeaderOptsProvider, options ...RequestOption) (Response, error) {

	options = append(options, addDefaultTimeout(fab.Query))
	options = append(options, addDefaultTargetFilter(cc.context, filter.ChaincodeQuery))

	return callBsnQueryHasOpts(cc, request, opts, options...)
}
