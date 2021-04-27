/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tls

import (
	gmx509 "github.com/tjfoc/gmsm/x509"
	"sync"
	"sync/atomic"

	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/logging"
	"github.com/BSNDA/fabric-sdk-go-gm/pkg/common/providers/fab"
)

var logger = logging.NewLogger("fabsdk/core")

// certPool is a thread safe wrapper around the x509 standard library
// cert pool implementation.
// It optionally allows loading the system trust store.
type certPool struct {
	certPool       *gmx509.CertPool
	certs          []*gmx509.Certificate
	certsByName    map[string][]int
	lock           sync.RWMutex
	dirty          int32
	systemCertPool bool
}

// NewCertPool new CertPool implementation
func NewCertPool(useSystemCertPool bool) (fab.CertPool, error) {

	c, err := loadSystemCertPool(useSystemCertPool)
	if err != nil {
		return nil, err
	}

	newCertPool := &certPool{
		certsByName:    make(map[string][]int),
		certPool:       c,
		systemCertPool: useSystemCertPool,
	}

	return newCertPool, nil
}

//Get returns certpool
//if there are any certs in cert queue added by any previous Add() call, it adds those certs to certpool before returning
func (c *certPool) Get() (*gmx509.CertPool, error) {

	//if dirty then add certs from queue to cert pool
	if atomic.CompareAndSwapInt32(&c.dirty, 1, 0) {
		//swap certpool if queue is dirty
		err := c.swapCertPool()
		if err != nil {
			return nil, err
		}
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.certPool, nil
}

//Add adds given certs to cert pool queue, those certs will be added to certpool during subsequent Get() call
func (c *certPool) Add(certs ...*gmx509.Certificate) {
	if len(certs) == 0 {
		return
	}

	//filter certs to be added, check if they already exist or duplicate
	certsToBeAdded := c.filterCerts(certs...)

	if len(certsToBeAdded) > 0 {

		c.lock.Lock()
		defer c.lock.Unlock()

		for _, newCert := range certsToBeAdded {
			// Store cert name index
			name := string(newCert.RawSubject)
			c.certsByName[name] = append(c.certsByName[name], len(c.certs))
			// Store cert
			c.certs = append(c.certs, newCert)
		}

		atomic.CompareAndSwapInt32(&c.dirty, 0, 1)
	}
}

func (c *certPool) swapCertPool() error {

	newCertPool, err := loadSystemCertPool(c.systemCertPool)
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	//add all new certs in queue to new cert pool
	for _, cert := range c.certs {
		newCertPool.AddCert(cert)
	}

	//swap old certpool with new one
	c.certPool = newCertPool

	return nil
}

//filterCerts remove certs from list if they already exist in pool or duplicate
func (c *certPool) filterCerts(certs ...*gmx509.Certificate) []*gmx509.Certificate {
	c.lock.RLock()
	defer c.lock.RUnlock()

	filtered := []*gmx509.Certificate{}

CertLoop:
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		possibilities := c.certsByName[string(cert.RawSubject)]
		for _, p := range possibilities {
			if c.certs[p].Equal(cert) {
				continue CertLoop
			}
		}
		filtered = append(filtered, cert)
	}

	//remove duplicate from list of certs being passed
	return removeDuplicates(filtered...)
}

func removeDuplicates(certs ...*gmx509.Certificate) []*gmx509.Certificate {
	encountered := map[*gmx509.Certificate]bool{}
	result := []*gmx509.Certificate{}

	for v := range certs {
		if !encountered[certs[v]] {
			encountered[certs[v]] = true
			result = append(result, certs[v])
		}
	}
	return result
}

func loadSystemCertPool(useSystemCertPool bool) (*gmx509.CertPool, error) {
	if !useSystemCertPool {
		return gmx509.NewCertPool(), nil
	}
	systemCertPool, err := gmx509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	logger.Debugf("Loaded system cert pool of size: %d", len(systemCertPool.Subjects()))

	return systemCertPool, nil
}
