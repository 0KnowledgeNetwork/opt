// related katzenpost:authority/voting/server/state.go

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"

	"github.com/0KnowledgeNetwork/appchain-agent/clients/go/chainbridge"
	"github.com/0KnowledgeNetwork/opt/pki/config"
)

const (
	stateBootstrap        = "bootstrap"
	stateWaitBlockDesc    = "wait_block_desc"
	stateAcceptDescriptor = "accept_desc"
	stateAcceptVote       = "accept_vote"
	stateConfirmConsensus = "confirm_consensus"

	publicKeyHashSize = 32
)

// NOTE: 2024-11-01:
// Parts of katzenpost use MixPublishDeadline and PublishConsensusDeadline defined in
// katzenpost:authority/voting/server/state.go
// So, we preserve that aspect of the epoch schedule.
var (
	MixPublishDeadline       = epochtime.Period * 1 / 8 // Do NOT change this
	DescriptorBlockDeadline  = epochtime.Period * 2 / 8
	AuthorityVoteDeadline    = epochtime.Period * 3 / 8
	PublishConsensusDeadline = epochtime.Period * 5 / 8 // Do NOT change this
	DocGenerationDeadline    = epochtime.Period * 7 / 8
	errGone                  = errors.New("authority: Requested epoch will never get a Document")
	errNotYet                = errors.New("authority: Document is not ready yet")
	errInvalidTopology       = errors.New("authority: Invalid Topology")
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

	documents map[uint64]*pki.Document

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
	s.log.Debugf("Current epoch %d, remaining time: %s, state: %s", epoch, nextEpoch, s.state)

	switch s.state {
	case stateBootstrap:
		// TODO: ensure network is ready and locally registered node is eligible for participation
		s.genesisEpoch = 0
		s.backgroundFetchConsensus(epoch - 1)
		s.backgroundFetchConsensus(epoch)
		if elapsed > MixPublishDeadline {
			s.log.Errorf("Too late to vote this round, sleeping until %s", nextEpoch)
			sleep = nextEpoch
			s.votingEpoch = epoch + 2
			s.state = stateBootstrap
		} else {
			s.votingEpoch = epoch + 1
			s.state = stateWaitBlockDesc
			sleep = MixPublishDeadline - elapsed
			if sleep < 0 {
				sleep = 0
			}
			s.log.Noticef("Bootstrapping for %d", s.votingEpoch)
		}
	case stateWaitBlockDesc:
		// Wait for appchain block production of all registered descriptors
		s.state = stateAcceptDescriptor
		sleep = DescriptorBlockDeadline - elapsed
	case stateAcceptDescriptor:
		doc, err := s.getVote(s.votingEpoch)
		if err == nil {
			s.log.Noticef("authority: FSM: Sending vote for epoch %d in epoch %d", s.votingEpoch, epoch)
			s.sendVoteToAppchain(doc, s.votingEpoch)
		} else {
			s.log.Errorf("Failed to compute vote for epoch %v: %s", s.votingEpoch, err)
		}
		s.state = stateAcceptVote
		_, nowelapsed, _ := epochtime.Now()
		sleep = AuthorityVoteDeadline - nowelapsed
	case stateAcceptVote:
		s.backgroundFetchConsensus(s.votingEpoch)
		s.state = stateConfirmConsensus
		_, nowelapsed, _ := epochtime.Now()
		sleep = PublishConsensusDeadline - nowelapsed
	case stateConfirmConsensus:
		// See if consensus doc was retrieved from the appchain
		_, ok := s.documents[epoch+1]
		if ok {
			s.state = stateWaitBlockDesc
			sleep = MixPublishDeadline + nextEpoch
			s.votingEpoch++
		} else {
			s.log.Error("No document for epoch %v", epoch+1)
			s.state = stateBootstrap
			s.votingEpoch = epoch + 2 // vote on epoch+2 in epoch+1
			sleep = nextEpoch
		}
	default:
	}
	s.pruneDocuments()
	s.log.Debugf("authority: FSM in state %v until %s", s.state, sleep)
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
	// TODO: use an appchain block hash as srv
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

	// We prefer to not randomize the topology if there is an existing topology to avoid
	// partitioning the client anonymity set when messages from an earlier epoch are
	// differentiable as such because of topology violations in the present epoch.
	if d, ok := s.documents[s.votingEpoch-1]; ok {
		topology = s.generateTopology(nodes, d, srv)
	} else {
		topology = s.generateRandomTopology(nodes, srv)
	}

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

func (s *state) generateTopology(nodeList []*pki.MixDescriptor, doc *pki.Document, srv []byte) [][]*pki.MixDescriptor {
	s.log.Debugf("Generating mix topology.")

	nodeMap := make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor)
	for _, v := range nodeList {
		id := hash.Sum256(v.IdentityKey)
		nodeMap[id] = v
	}

	// TODO: consider strategies for balancing topology? Should this happen automatically?
	//       the current strategy will rebalance by limiting the number of nodes that are
	//       (re)inserted at each layer and placing these nodes into another layer.

	// Since there is an existing network topology, use that as the basis for
	// generating the mix topology such that the number of nodes per layer is
	// approximately equal, and as many nodes as possible retain their existing
	// layer assignment to minimise network churn.
	// The srv is used, when available, to ensure the ordering of new nodes
	// is deterministic between authorities
	rng, err := rand.NewDeterministicRandReader(srv[:])
	if err != nil {
		s.log.Errorf("DeterministicRandReader() failed to initialize: %v", err)
		s.s.fatalErrCh <- err
	}
	targetNodesPerLayer := len(nodeList) / s.s.cfg.Debug.Layers
	topology := make([][]*pki.MixDescriptor, s.s.cfg.Debug.Layers)

	// Assign nodes that still exist up to the target size.
	for layer, nodes := range doc.Topology {
		nodeIndexes := rng.Perm(len(nodes))

		for _, idx := range nodeIndexes {
			if len(topology[layer]) >= targetNodesPerLayer {
				break
			}

			id := hash.Sum256(nodes[idx].IdentityKey)
			if n, ok := nodeMap[id]; ok {
				// There is a new descriptor with the same identity key,
				// as an existing descriptor in the previous document,
				// so preserve the layering.
				topology[layer] = append(topology[layer], n)
				delete(nodeMap, id)
			}
		}
	}

	// Flatten the map containing the nodes pending assignment.
	toAssign := make([]*pki.MixDescriptor, 0, len(nodeMap))
	for _, n := range nodeMap {
		toAssign = append(toAssign, n)
	}
	// must sort toAssign by ID!
	sortNodesByPublicKey(toAssign)

	assignIndexes := rng.Perm(len(toAssign))

	// Fill out any layers that are under the target size, by
	// randomly assigning from the pending list.
	idx := 0
	for layer := range doc.Topology {
		for len(topology[layer]) < targetNodesPerLayer {
			n := toAssign[assignIndexes[idx]]
			topology[layer] = append(topology[layer], n)
			idx++
		}
	}

	// Assign the remaining nodes.
	for layer := 0; idx < len(assignIndexes); idx++ {
		n := toAssign[assignIndexes[idx]]
		topology[layer] = append(topology[layer], n)
		layer++
		layer = layer % len(topology)
	}

	return topology
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
}

// Ensure that the descriptor is from an allowed peer according to the appchain
func (s *state) isDescriptorAuthorized(desc *pki.MixDescriptor) bool {
	node, err := s.chNodesGet(desc.Name)
	if err != nil {
		s.log.Debugf("state: Failed to retrive node=%s from appchain: %v", desc.Name, err)
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
	pk := hash.Sum256(desc.IdentityKey)

	s.RLock()
	doc := s.documents[epoch]
	s.RUnlock()

	if doc != nil {
		// If there is a document already, the descriptor is late, and will
		// never appear in a document, so reject it.
		return fmt.Errorf("pki: ❌ Node %x: Late descriptor upload for epoch %v", pk, epoch)
	}

	// Register the mix descriptor with the appchain, which will:
	// - reject redundant descriptors (even those that didn't change)
	// - reject descriptors if document for the epoch exists
	if err := s.chPKISetMixDescriptor(desc, epoch); err != nil {
		return fmt.Errorf("pki: ❌ Failed to set mix descriptor for node %d, epoch=%v: %v", desc.Name, epoch, err)
	}

	epochCurrent, _, _ := epochtime.Now()
	s.log.Noticef("pki: ✅ Submitted descriptor to appchain for Node name=%v, epoch=%v (in epoch=%v)", desc.Name, epoch, epochCurrent)
	return nil
}

func (s *state) documentForEpoch(epoch uint64) ([]byte, error) {
	s.log.Debugf("pki: documentForEpoch(%v)", epoch)

	s.RLock()
	defer s.RUnlock()

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

	st.documents = make(map[uint64]*pki.Document)

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

func sortNodesByPublicKey(nodes []*pki.MixDescriptor) {
	dTos := func(d *pki.MixDescriptor) string {
		pk := hash.Sum256(d.IdentityKey)
		return string(pk[:])
	}
	sort.Slice(nodes, func(i, j int) bool { return dTos(nodes[i]) < dTos(nodes[j]) })
}
