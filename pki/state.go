// related katzenpost:authority/voting/server/state.go

// 2024-07-02 This file is an iterative shim to be replaced with AppChain interactions.

package main

import (
	"errors"
	"fmt"
	"math"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"

	"github.com/0KnowledgeNetwork/appchain-agent/clients/go/chainbridge"
	"github.com/0KnowledgeNetwork/opt/pki/config"
)

const (
	publicKeyHashSize = 32
)

// TODO: retrieve epoch schedule from appchain
var (
	DescriptorUploadDeadline = epochtime.Period / 4
	DocGenerationDeadline    = epochtime.Period * 3 / 4
	errGone                  = errors.New("pki: Requested epoch will never get a Document")
	errNotYet                = errors.New("pki: Document is not ready yet")
)

type state struct {
	s           *Server
	log         *logging.Logger
	chainBridge *chainbridge.ChainBridge

	documents   map[uint64]*pki.Document
	descriptors map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor

	votingEpoch  uint64
	genesisEpoch uint64
}

// from katzenpost:authority/voting/server/server.go
func computeLambdaG(cfg *config.Config) float64 {
	n := float64(len(cfg.Topology.Layers[0].Nodes))
	if n == 1 {
		return cfg.Parameters.LambdaP + cfg.Parameters.LambdaL + cfg.Parameters.LambdaD
	}
	return n * math.Log(n)
}

func (s *state) doSignDocument(signer sign.PrivateKey, verifier sign.PublicKey, d *pki.Document) ([]byte, error) {
	signAt := time.Now()
	sig, err := pki.SignDocument(signer, verifier, d)
	s.log.Noticef("pki.SignDocument took %v", time.Since(signAt))
	return sig, err
}

func (s *state) getDocument(descriptors []*pki.MixDescriptor, params *config.Parameters, srv []byte) *pki.Document {
	// Carve out the descriptors between providers and nodes.
	gateways := []*pki.MixDescriptor{}
	serviceNodes := []*pki.MixDescriptor{}
	nodes := []*pki.MixDescriptor{}

	for _, v := range descriptors {
		if v.IsGatewayNode {
			gateways = append(gateways, v)
		} else if v.IsServiceNode {
			serviceNodes = append(serviceNodes, v)
		} else {
			nodes = append(nodes, v)
		}
	}

	// Assign nodes to layers.
	var topology [][]*pki.MixDescriptor

	// FIXME: Topology -- use the simplest as placeholder for now
	// We prefer to not randomize the topology if there is an existing topology to avoid
	// partitioning the client anonymity set when messages from an earlier epoch are
	// differentiable as such because of topology violations in the present epoch.
	topology = s.generateRandomTopology(nodes, srv)

	lambdaG := computeLambdaG(s.s.cfg)
	s.log.Debugf("computed lambdaG is %f", lambdaG)

	// Build the Document.
	doc := &pki.Document{
		Epoch:              s.votingEpoch,
		GenesisEpoch:       s.genesisEpoch,
		SendRatePerMinute:  params.SendRatePerMinute,
		Mu:                 params.Mu,
		MuMaxDelay:         params.MuMaxDelay,
		LambdaP:            params.LambdaP,
		LambdaPMaxDelay:    params.LambdaPMaxDelay,
		LambdaL:            params.LambdaL,
		LambdaLMaxDelay:    params.LambdaLMaxDelay,
		LambdaD:            params.LambdaD,
		LambdaDMaxDelay:    params.LambdaDMaxDelay,
		LambdaM:            params.LambdaM,
		LambdaMMaxDelay:    params.LambdaMMaxDelay,
		LambdaG:            lambdaG,
		LambdaGMaxDelay:    params.LambdaGMaxDelay,
		Topology:           topology,
		GatewayNodes:       gateways,
		ServiceNodes:       serviceNodes,
		SharedRandomValue:  srv,
		PriorSharedRandom:  [][]byte{srv}, // this is made up, only to suffice IsDocumentWellFormed
		SphinxGeometryHash: s.s.geo.Hash(),
		PKISignatureScheme: s.s.cfg.Server.PKISignatureScheme,
	}
	return doc
}

func (s *state) generateRandomTopology(nodes []*pki.MixDescriptor, srv []byte) [][]*pki.MixDescriptor {
	s.log.Debugf("Generating random mix topology.")

	// If there is no node history in the form of a previous consensus,
	// then the simplest thing to do is to randomly assign nodes to the
	// various layers.

	if len(srv) != 32 {
		err := errors.New("SharedRandomValue too short")
		s.log.Errorf("srv: %s", srv)
		s.s.fatalErrCh <- err
	}
	rng, err := rand.NewDeterministicRandReader(srv[:])
	if err != nil {
		s.log.Errorf("DeterministicRandReader() failed to initialize: %v", err)
		s.s.fatalErrCh <- err
	}

	nodeIndexes := rng.Perm(len(nodes))
	topology := make([][]*pki.MixDescriptor, s.s.cfg.Debug.Layers)
	for idx, layer := 0, 0; idx < len(nodes); idx++ {
		n := nodes[nodeIndexes[idx]]
		topology[layer] = append(topology[layer], n)
		layer++
		layer = layer % len(topology)
	}

	return topology
}

func (s *state) pruneDocuments() {
	// Looking a bit into the past is probably ok, if more past documents
	// need to be accessible, then methods that query the DB could always
	// be added.
	const preserveForPastEpochs = 3

	now, _, _ := epochtime.Now()
	cmpEpoch := now - preserveForPastEpochs

	for e := range s.documents {
		if e < cmpEpoch {
			delete(s.documents, e)
		}
	}
	for e := range s.descriptors {
		if e < cmpEpoch {
			delete(s.descriptors, e)
		}
	}
}

// FIXME: Ensure that the descriptor is from an allowed peer.
// TODO: consult with the appChain
func (s *state) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	s.log.Debugf("TODO: check appchain for isDescriptorAuthorized: name: %v", desc.Name)

	// pk := hash.Sum256(desc.IdentityKey)
	// if !desc.IsGatewayNode && !desc.IsServiceNode {
	// 	return s.authorizedMixes[pk]
	// }
	// if desc.IsGatewayNode {
	// 	name, ok := s.authorizedGatewayNodes[pk]
	// 	if !ok {
	// 		return false
	// 	}
	// 	return name == desc.Name
	// }
	// if desc.IsServiceNode {
	// 	name, ok := s.authorizedServiceNodes[pk]
	// 	if !ok {
	// 		return false
	// 	}
	// 	return name == desc.Name
	// }
	// panic("impossible")

	return true // FIXME
}

func (s *state) onDescriptorUpload(rawDesc []byte, desc *pki.MixDescriptor, epoch uint64) error {
	// Note: Caller ensures that the epoch is the current epoch +- 1.

	_ = rawDesc // unused, but retain function interface

	_, elapsed, _ := epochtime.Now()
	if elapsed > DescriptorUploadDeadline {
		return fmt.Errorf("state: Node %v: Late descriptor upload for for epoch %v", desc.IdentityKey, epoch)
	}

	// Register the mix descriptor with the appchain, which will:
	// - reject redundant descriptors (even those that didn't change)
	// - reject descriptors if document for the epoch exists
	payload, err := desc.MarshalBinary()
	if err != nil {
		return fmt.Errorf("state: failed to marshal descriptor: %v", err)
	}
	chCommand := fmt.Sprintf("pki setMixDescriptor %d %s", epoch, desc.Name)
	chResponse, err := s.chainBridge.Command(chCommand, payload)
	s.log.Debugf("ChainBridge response (%s): %+v", chCommand, chResponse)
	if err != nil {
		return fmt.Errorf("state: ChainBridge command error: %v", err)
	}
	if chResponse.Error != "" {
		return fmt.Errorf("state: ChainBridge response error: %v", chResponse.Error)
	}

	s.log.Noticef("Successfully submitted descriptor for id=%v, epoch=%v", desc.Name, epoch)
	return nil
}

// generate docs based on the current epoch schedule
// this is just a placeholder to trigger document generation
// or retrieval from appchain
func (s *state) update() error {
	epoch, elapsed, nextEpoch := epochtime.Now()

	// generate a doc for the next epoch after the descriptor upload deadline
	if elapsed > DescriptorUploadDeadline && s.documents[epoch+1] == nil {
		s.votingEpoch = epoch + 1

		// retrieve PKI doc from appchain if one already exists for the epoch
		chCommand := fmt.Sprintf("pki getDocument %d", s.votingEpoch)
		chResponse, err := s.chainBridge.Command(chCommand, nil)
		if err != nil {
			return fmt.Errorf("state: ChainBridge command error: %v", err)
		}
		chDoc, err := s.chainBridge.GetDataBytes(chResponse)
		if err == nil {
			var doc pki.Document
			if err = doc.UnmarshalBinary(chDoc); err != nil {
				return fmt.Errorf("state: failed to unmarshal PKI document: %v", err)
			} else {
				// store PKI doc locally
				s.documents[s.votingEpoch] = &doc
				s.log.Debugf("pki: ✅ Retrieved doc for epoch %v: %s", s.votingEpoch, doc.String())
				s.pruneDocuments()
				return nil
			}
		}

		// according to the appchain, there's not yet a PKI doc for the epoch, so generate it

		// get number of descriptors for the given epoch from appchain
		chCommand = fmt.Sprintf("pki getMixDescriptorCounter %d", s.votingEpoch)
		chResponse, err = s.chainBridge.Command(chCommand, nil)
		if err != nil {
			return fmt.Errorf("state: ChainBridge command error: %v", err)
		}
		numDescriptors, err := s.chainBridge.GetDataUInt(chResponse)
		if err != nil && err != chainbridge.ErrNoData {
			return fmt.Errorf("state: ChainBridge data error: %v", err)
		}

		if s.genesisEpoch == 0 {
			// if no descriptors, the pki probably started too late in the epoch
			if numDescriptors == 0 {
				s.log.Debugf("pki: Epoch %d is gone; a potential genesis epoch but no descriptors", s.votingEpoch)
				return errGone
			}

			// get genesis epoch from appchain
			chResponse, err := s.chainBridge.Command("pki getGenesisEpoch", nil)
			if err != nil {
				return fmt.Errorf("state: ChainBridge command error: %v", err)
			}
			genesisEpoch, err := s.chainBridge.GetDataUInt(chResponse)
			if err != nil {
				return fmt.Errorf("state: ChainBridge data error: %v", err)
			}

			// if appchain has descriptors, it also has genesis epoch, so set it here
			s.genesisEpoch = genesisEpoch
		}

		s.log.Debugf("pki: ⭐ Generating doc for epoch %d, elapsed: %s (> %s), remaining time: %s", s.votingEpoch, elapsed, DescriptorUploadDeadline, nextEpoch)

		// get descriptors from appchain for the approaching epoch
		descriptors := []*pki.MixDescriptor{}
		for i := 0; i < int(numDescriptors); i++ {
			chCommand := fmt.Sprintf("pki getMixDescriptorByIndex %d %d", s.votingEpoch, i)
			chResponse, err := s.chainBridge.Command(chCommand, nil)
			if err != nil {
				s.log.Error("ChainBridge command error: %v", err)
				continue
			}
			dataAsBytes, err := s.chainBridge.GetDataBytes(chResponse)
			if err != nil {
				s.log.Error("ChainBridge data error: %v", err)
				continue
			}

			var desc pki.MixDescriptor
			if err = desc.UnmarshalBinary(dataAsBytes); err != nil {
				s.log.Error("Failed to unmarshal descriptor: %v", err)
				continue
			}
			descriptors = append(descriptors, &desc)
		}

		var zeros [32]byte
		doc := s.getDocument(descriptors, s.s.cfg.Parameters, zeros[:])
		_, err = s.doSignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, doc)
		if err != nil {
			return err
		}

		// FIXME: If doc is not wellformed, it currently spins up to this point
		// continually trying to generate a doc, but not having any new information.
		// In this case, the epoch failed.
		err = pki.IsDocumentWellFormed(doc, nil)
		if err != nil {
			s.log.Errorf("pki: ❌ IsDocumentWellFormed: %s", err)
			return errGone
		}

		// register the PKI doc with the appchain
		payload, err := doc.MarshalBinary()
		if err != nil {
			return fmt.Errorf("state: failed to marshal PKI document: %v", err)
		}
		chCommand = fmt.Sprintf("pki setDocument %d", s.votingEpoch)
		chResponse, err = s.chainBridge.Command(chCommand, payload)
		s.log.Debugf("ChainBridge response (%s): %+v\n", chCommand, chResponse)
		if err != nil {
			s.log.Error("ChainBridge command error: %v", err)
			return err
		}
		if chResponse.Error != "" {
			s.log.Errorf("ChainBridge response error: %v", chResponse.Error)
			return errors.New(chResponse.Error)
		}

		// store PKI doc locally
		s.documents[s.votingEpoch] = doc

		s.log.Debugf("pki: ✅ Generated doc for epoch %v: %s", s.votingEpoch, doc.String())
		s.pruneDocuments()
	}

	return nil
}

func (s *state) documentForEpoch(epoch uint64) ([]byte, error) {
	s.log.Debugf("pki: documentForEpoch(%v)", epoch)

	// generate or retrieve docs based on the epoch schedule
	err := s.update()
	if err != nil {
		return nil, err
	}

	// If we have a serialized document, return it.
	if d, ok := s.documents[epoch]; ok {
		// XXX We should cache this
		return d.MarshalBinary()
	}

	// Otherwise, return an error based on the time.
	now, elapsed, _ := epochtime.Now()
	switch epoch {
	case now:
		// We missed the deadline to publish a descriptor for the current
		// epoch, so we will never be able to service this request.
		s.log.Errorf("No document for current epoch %v generated and never will be", now)
		return nil, errGone
	case now + 1:
		// If it's past the time by which we should have generated a document
		// then we will never be able to service this.
		if elapsed > DocGenerationDeadline {
			s.log.Errorf("No document for next epoch %v and it's already past DocGenerationDeadline of previous epoch", now+1)
			return nil, errGone
		}
		return nil, errNotYet
	default:
		if epoch < now {
			// Requested epoch is in the past, and it's not in the cache.
			// We will never be able to satisfy this request.
			s.log.Errorf("No document for epoch %v, because we are already in %v", epoch, now)
			return nil, errGone
		}
		return nil, fmt.Errorf("state: Request for invalid epoch: %v", epoch)
	}

	// NOTREACHED
}

func newState(s *Server) (*state, error) {
	st := new(state)
	st.s = s
	st.log = s.logBackend.GetLogger("state")

	chainBridgeLogger := s.logBackend.GetLogger("state:chainBridge")
	st.chainBridge = chainbridge.NewChainBridge("/appchain_mixnet/appchain.sock")
	st.chainBridge.SetErrorHandler(func(err error) {
		chainBridgeLogger.Errorf("Error: %v", err)
	})
	st.chainBridge.SetLogHandler(func(msg string) {
		chainBridgeLogger.Infof(msg)
	})
	if err := st.chainBridge.Start(); err != nil {
		chainBridgeLogger.Fatalf("Error: %v", err)
	}

	// set voting schedule at runtime
	// TODO: retrieve from appchain

	st.log.Debugf("State initialized with epoch Period: %s", epochtime.Period)
	st.log.Debugf("State initialized with DescriptorUploadDeadline: %s", DescriptorUploadDeadline)
	st.log.Debugf("State initialized with DocGenerationDeadline: %s", DocGenerationDeadline)

	st.documents = make(map[uint64]*pki.Document)
	st.descriptors = make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor)

	epoch, elapsed, nextEpoch := epochtime.Now()
	st.log.Debugf("Epoch: %d, elapsed: %s, remaining time: %s", epoch, elapsed, nextEpoch)

	return st, nil
}
