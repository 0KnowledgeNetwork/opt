// AppChain communication (chainbridge) functions

package main

import (
	"fmt"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/katzenpost/core/pki"

	"github.com/0KnowledgeNetwork/appchain-agent/clients/go/chainbridge"
	"github.com/0KnowledgeNetwork/opt/pki/config"
)

func (s *state) chNodesGet(name string) (*chainbridge.Node, error) {
	chCommand := fmt.Sprintf(chainbridge.Cmd_nodes_getNode, name)
	chResponse, err := s.chainBridge.Command(chCommand, nil)
	if err != nil {
		return nil, fmt.Errorf("state: ChainBridge command error: %v", err)
	}

	var node chainbridge.Node
	if err = s.chainBridge.DataUnmarshal(chResponse, &node); err != nil {
		return nil, err
	}

	return &node, nil
}

func (st *state) chNodesRegister(v *config.Node, isGatewayNode bool, isServiceNode bool) {
	pkiSignatureScheme := signSchemes.ByName(st.s.cfg.Server.PKISignatureScheme)

	var err error
	var identityPublicKey sign.PublicKey
	if filepath.IsAbs(v.IdentityPublicKeyPem) {
		identityPublicKey, err = signpem.FromPublicPEMFile(v.IdentityPublicKeyPem, pkiSignatureScheme)
		if err != nil {
			panic(err)
		}
	} else {
		pemFilePath := filepath.Join(st.s.cfg.Server.DataDir, v.IdentityPublicKeyPem)
		identityPublicKey, err = signpem.FromPublicPEMFile(pemFilePath, pkiSignatureScheme)
		if err != nil {
			panic(err)
		}
	}

	payload, err := identityPublicKey.MarshalBinary()
	if err != nil {
		st.log.Errorf("failed to marshal identityPublicKey: %v", err)
		return
	}
	pk := hash.Sum256From(identityPublicKey)
	chCommand := fmt.Sprintf(
		chainbridge.Cmd_nodes_register,
		v.Identifier,
		chainbridge.Bool2int(isGatewayNode),
		chainbridge.Bool2int(isServiceNode))
	chResponse, err := st.chainBridge.Command(chCommand, payload)
	st.log.Debugf("ChainBridge response (%s): %+v", chCommand, chResponse)
	if err != nil {
		st.log.Errorf("ChainBridge command error: %v", err)
		return
	}
	if chResponse.Error != "" && chResponse.Error != chainbridge.Err_nodes_alreadyRegistered {
		st.log.Errorf("ChainBridge response error: %v", chResponse.Error)
		return
	}

	st.registeredLocalNodes[pk] = true
	st.log.Noticef("Local node registered with Identifier '%s', Identity key hash '%x'", v.Identifier, pk)
}

func (s *state) chPKIGetGenesisEpoch() (uint64, error) {
	chResponse, err := s.chainBridge.Command(chainbridge.Cmd_pki_getGenesisEpoch, nil)
	if err != nil {
		return 0, fmt.Errorf("state: ChainBridge command error: %v", err)
	}
	genesisEpoch, err := s.chainBridge.GetDataUInt(chResponse)
	if err != nil {
		return 0, fmt.Errorf("state: ChainBridge data error: %v", err)
	}
	return genesisEpoch, nil
}

func (s *state) chPKIGetDocument(epoch uint64) (*pki.Document, error) {
	chCommand := fmt.Sprintf(chainbridge.Cmd_pki_getDocucment, epoch)
	chResponse, err := s.chainBridge.Command(chCommand, nil)
	if err != nil {
		return nil, fmt.Errorf("state: ChainBridge command error: %v", err)
	}

	chDoc, err := s.chainBridge.GetDataBytes(chResponse)
	if err != nil {
		return nil, err
	}

	var doc pki.Document
	// X: if err = doc.UnmarshalCertificate(chDoc); err != nil {
	if err = cbor.Unmarshal(chDoc, (*pki.Document)(&doc)); err != nil {
		return nil, fmt.Errorf("state: failed to unmarshal PKI document: %v", err)
	}

	return &doc, nil
}

// register the PKI doc with the appchain
func (s *state) chPKISetDocument(doc *pki.Document) error {
	// register with the appchain an unsigned certificate-less doc,
	// so authorities submit the same doc hash as their vote
	// X: payload, err := doc.MarshalCertificate()
	payload, err := s.ccbor.Marshal((*pki.Document)(doc))
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("state: failed to marshal PKI document: %v", err)
	}
	chCommand := fmt.Sprintf(chainbridge.Cmd_pki_setDocument, doc.Epoch)
	chResponse, err := s.chainBridge.Command(chCommand, payload)
	s.log.Debugf("ChainBridge response (%s): %+v", chCommand, chResponse)
	if err != nil {
		return fmt.Errorf("state: ChainBridge command error: %v", err)
	}

	// ignore the most likely chResponse.Error: "Document already exists for the epoch"
	// if chResponse.Error != "" {
	//   return fmt.Errorf("state: ChainBridge response error: %v", chResponse.Error)
	// }

	return nil
}

// get number of descriptors for the given epoch from appchain
func (s *state) chPKIGetMixDescriptorCounter(epoch uint64) (uint64, error) {
	chCommand := fmt.Sprintf(chainbridge.Cmd_pki_getMixDescriptorCounter, epoch)
	chResponse, err := s.chainBridge.Command(chCommand, nil)
	if err != nil {
		return 0, fmt.Errorf("state: ChainBridge command error: %v", err)
	}
	numDescriptors, err := s.chainBridge.GetDataUInt(chResponse)
	if err != nil && err != chainbridge.ErrNoData {
		return 0, fmt.Errorf("state: ChainBridge data error: %v", err)
	}
	return numDescriptors, nil
}

func (s *state) chPKIGetMixDescriptors(epoch uint64) ([]*pki.MixDescriptor, error) {
	numDescriptors, err := s.chPKIGetMixDescriptorCounter(epoch)
	if err != nil {
		return nil, err
	}

	descriptors := []*pki.MixDescriptor{}
	for i := 0; i < int(numDescriptors); i++ {
		chCommand := fmt.Sprintf(chainbridge.Cmd_pki_getMixDescriptorByIndex, epoch, i)
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

	return descriptors, nil
}

// Register the mix descriptor with the appchain, which will:
// - reject redundant descriptors (even those that didn't change)
// - reject descriptors if document for the epoch exists
func (s *state) chPKISetMixDescriptor(desc *pki.MixDescriptor, epoch uint64) error {
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
	return nil
}
