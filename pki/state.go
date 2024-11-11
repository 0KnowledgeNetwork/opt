// related katzenpost:authority/voting/server/state.go

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"

	"github.com/0KnowledgeNetwork/appchain-agent/clients/go/chainbridge"
	"github.com/0KnowledgeNetwork/opt/pki/config"
)

const (
	stateBootstrap        = "bootstrap"
	stateAcceptDescriptor = "accept_desc"
	stateAcceptVote       = "accept_vote"
	stateAcceptReveal     = "accept_reveal"
	stateAcceptCert       = "accept_cert"
	stateAcceptSignature  = "accept_signature"

	publicKeyHashSize = 32
)

// NOTE: 2024-11-01:
// Parts of katzenpost use MixPublishDeadline and PublishConsensusDeadline defined in
// katzenpost:authority/voting/server/state.go
// So, we preserve that aspect of the epoch schedule.
var (
	MixPublishDeadline       = epochtime.Period / 8
	AuthorityVoteDeadline    = MixPublishDeadline + epochtime.Period/8
	AuthorityRevealDeadline  = AuthorityVoteDeadline + epochtime.Period/8
	AuthorityCertDeadline    = AuthorityRevealDeadline + epochtime.Period/8
	PublishConsensusDeadline = AuthorityCertDeadline + epochtime.Period/8
	errGone                  = errors.New("authority: Requested epoch will never get a Document")
	errNotYet                = errors.New("authority: Document is not ready yet")
	errInvalidTopology       = errors.New("authority: Invalid Topology")
)

// Custom epoch schedule for appchain PKI
var (
	DescriptorUploadDeadline = MixPublishDeadline
	DocGenerationDeadline    = epochtime.Period * 7 / 8
)

type state struct {
	sync.RWMutex
	worker.Worker

	s           *Server
	log         *logging.Logger
	chainBridge *chainbridge.ChainBridge
	ccbor       cbor.EncMode // a la katzenpost:core/pki/document.go

	// locally registered node(s), only one allowed
	// authority authentication for descriptor uploads is limited to this
	registeredLocalNodes map[[publicKeyHashSize]byte]bool

	documents   map[uint64]*pki.Document
	descriptors map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor

	votingEpoch  uint64
	genesisEpoch uint64
	state        string
}

func (s *state) Halt() {
	s.Worker.Halt()
}

func (s *state) worker() {
	for {
		select {
		case <-s.HaltCh():
			s.log.Debugf("authority: Terminating gracefully.")
			return
		case <-s.fsm():
			s.log.Debugf("authority: Wakeup due to voting schedule.")
		}
	}
}

func (s *state) fsm() <-chan time.Time {
	s.Lock()
	var sleep time.Duration
	epoch, elapsed, nextEpoch := epochtime.Now()
	s.log.Debugf("✨ pki: FSM: Current epoch %d, remaining time: %s", epoch, nextEpoch)

	switch s.state {
	case stateBootstrap:
		s.genesisEpoch = 0
		s.backgroundFetchConsensus(epoch - 1)
		s.backgroundFetchConsensus(epoch)
		if elapsed > MixPublishDeadline {
			s.log.Errorf("pki: FSM: Too late to vote this round, sleeping until %s", nextEpoch)
			sleep = nextEpoch
			s.votingEpoch = epoch + 2
			s.state = stateBootstrap
		} else {
			s.votingEpoch = epoch + 1
			s.state = stateAcceptDescriptor
			sleep = MixPublishDeadline - elapsed
			if sleep < 0 {
				sleep = 0
			}
			s.log.Noticef("pki: FSM: Bootstrapping for %d", s.votingEpoch)
		}

	case stateAcceptDescriptor:
		doc, err := s.getVote(s.votingEpoch)
		if err == nil {
			s.log.Noticef("pki: FSM: Sending vote for epoch %d in epoch %d", s.votingEpoch, epoch)
			s.sendVoteToAppchain(doc, s.votingEpoch)
		} else {
			s.log.Errorf("Failed to compute vote for epoch %v: %s", s.votingEpoch, err)
		}
		s.state = stateAcceptVote
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityVoteDeadline - nowelapsed

	case stateAcceptVote:
		s.backgroundFetchConsensus(s.votingEpoch)
		s.state = stateAcceptReveal
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityRevealDeadline - nowelapsed

	case stateAcceptReveal:
		s.state = stateAcceptCert
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityCertDeadline - nowelapsed

	case stateAcceptCert:
		s.state = stateAcceptSignature
		_, nowelapsed, _ := epochtime.Now()
		sleep = PublishConsensusDeadline - nowelapsed

	case stateAcceptSignature:
		s.state = stateBootstrap
		sleep = nextEpoch

	default:
	}
	s.pruneDocuments()
	s.log.Debugf("✨ pki: FSM in state %v until %s", s.state, sleep)
	s.Unlock()
	return time.After(sleep)
}

// getVote produces a pki.Document using all MixDescriptors recorded with the appchain
func (s *state) getVote(epoch uint64) (*pki.Document, error) {
	// Is there a prior consensus? If so, obtain the GenesisEpoch
	if d, ok := s.documents[s.votingEpoch-1]; ok {
		s.log.Debugf("Restoring genesisEpoch %d from document cache", d.GenesisEpoch)
		s.genesisEpoch = d.GenesisEpoch
		d.PKISignatureScheme = s.s.cfg.Server.PKISignatureScheme
	} else {
		s.log.Debugf("Setting genesisEpoch %d from votingEpoch", s.votingEpoch)
		s.genesisEpoch = s.votingEpoch
	}

	descriptors, err := s.chPKIGetMixDescriptors(epoch)
	if err != nil {
		return nil, err
	}

	// vote topology is irrelevent.
	var zeros [32]byte
	doc := s.getDocument(descriptors, s.s.cfg.Parameters, zeros[:])

	// Note: For appchain-pki, upload unsigned document and sign it upon local save.
	// simulate SignDocument's setting of doc version, required by IsDocumentWellFormed
	doc.Version = pki.DocumentVersion

	if err := pki.IsDocumentWellFormed(doc, nil); err != nil {
		s.log.Errorf("pki: ❌ getVote: IsDocumentWellFormed: %s", err)
		return nil, err
	}

	return doc, nil
}

func (s *state) sendVoteToAppchain(doc *pki.Document, epoch uint64) {
	if err := s.chPKISetDocument(doc); err != nil {
		s.log.Errorf("❌ sendVoteToAppchain: Error setting document for epoch %v: %v", epoch, err)
	}
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

	nodesPerLayer := len(nodes) / s.s.cfg.Debug.Layers
	lambdaG := computeLambdaGFromNodesPerLayer(s.s.cfg, nodesPerLayer)
	s.log.Debugf("computed lambdaG from %d nodes per layer is %f", nodesPerLayer, lambdaG)

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

// Ensure that the descriptor is from an allowed peer according to the appchain
func (s *state) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	chCommand := fmt.Sprintf(chainbridge.Cmd_nodes_getNode, desc.Name)
	chResponse, err := s.chainBridge.Command(chCommand, nil)
	if err != nil {
		s.log.Errorf("state: ChainBridge command error: %v", err)
		return false
	}

	var node chainbridge.Node
	err = s.chainBridge.DataUnmarshal(chResponse, &node)
	if err != nil {
		if err != chainbridge.ErrNoData {
			s.log.Errorf("state: ChainBridge data error: %v", err)
		}
		return false
	}

	pk := hash.Sum256(desc.IdentityKey)
	if pk != hash.Sum256(node.IdentityKey) {
		s.log.Debugf("state: IdentityKey mismatch for node %s", desc.Name)
		return false
	}

	if desc.IsGatewayNode != node.IsGatewayNode {
		return false
	}

	if desc.IsServiceNode != node.IsServiceNode {
		return false
	}

	return true
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
	chCommand := fmt.Sprintf(chainbridge.Cmd_pki_setMixDescriptor, epoch, desc.Name)
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

func (s *state) documentForEpoch(epoch uint64) ([]byte, error) {
	s.log.Debugf("pki: documentForEpoch(%v)", epoch)

	// If we have a serialized document, return it.
	if d, ok := s.documents[epoch]; ok {
		// XXX We should cache this
		return d.MarshalCertificate()
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

	ccbor, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	st.ccbor = ccbor

	chainBridgeLogger := s.logBackend.GetLogger("state:chainBridge")
	st.chainBridge = chainbridge.NewChainBridge(filepath.Join(s.cfg.Server.DataDir, "appchain.sock"))
	st.chainBridge.SetErrorHandler(func(err error) {
		chainBridgeLogger.Errorf("Error: %v", err)
	})
	st.chainBridge.SetLogHandler(func(msg string) {
		chainBridgeLogger.Infof(msg)
	})
	if err := st.chainBridge.Start(); err != nil {
		chainBridgeLogger.Fatalf("Error: %v", err)
	}

	// Initialize the authorized peer tables.
	st.registeredLocalNodes = make(map[[publicKeyHashSize]byte]bool)
	for _, v := range st.s.cfg.Mixes {
		st.chNodesRegister(v, false, false)
	}
	for _, v := range st.s.cfg.GatewayNodes {
		st.chNodesRegister(v, true, false)
	}
	for _, v := range st.s.cfg.ServiceNodes {
		st.chNodesRegister(v, false, true)
	}

	if len(st.registeredLocalNodes) > 1 {
		st.log.Fatalf("Error: Configuration found for more than one local node")
	}

	st.log.Debugf("State initialized with epoch Period: %s", epochtime.Period)
	st.log.Debugf("State initialized with DescriptorUploadDeadline: %s", DescriptorUploadDeadline)
	st.log.Debugf("State initialized with DocGenerationDeadline: %s", DocGenerationDeadline)

	st.documents = make(map[uint64]*pki.Document)
	st.descriptors = make(map[uint64]map[[publicKeyHashSize]byte]*pki.MixDescriptor)

	epoch, elapsed, nextEpoch := epochtime.Now()
	st.log.Debugf("Epoch: %d, elapsed: %s, remaining time: %s", epoch, elapsed, nextEpoch)

	// Set the initial state to bootstrap
	st.state = stateBootstrap
	return st, nil
}

func (s *state) backgroundFetchConsensus(epoch uint64) {
	if s.TryLock() {
		panic("write lock not held in backgroundFetchConsensus(epoch)")
	}

	// If there isn't a consensus for the previous epoch, ask the appchain for a consensus.
	_, ok := s.documents[epoch]
	if !ok {
		s.Go(func() {
			doc, err := s.chPKIGetDocument(epoch)
			if err != nil {
				s.log.Debugf("pki: FetchConsensus: Failed to fetch document for epoch %v: %v", epoch, err)
				return
			}
			s.Lock()
			defer s.Unlock()

			// It's possible that the state has changed
			// if backgroundFetchConsensus was called
			// multiple times during bootstrapping
			if _, ok := s.documents[epoch]; !ok {
				// sign the locally-stored document
				_, err := s.doSignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, doc)
				if err != nil {
					s.log.Errorf("pki: FetchConsensus: Error signing document for epoch %v: %v", epoch, err)
					return
				}
				s.documents[epoch] = doc
				s.log.Debugf("pki: FetchConsensus: ✅ Set doc for epoch %v: %s", epoch, doc.String())
			}
		})
	}
}
