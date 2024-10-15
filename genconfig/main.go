// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cConfig "github.com/katzenpost/katzenpost/client/config"
	cConfig2 "github.com/katzenpost/katzenpost/client2/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	sConfig "github.com/katzenpost/katzenpost/server/config"

	zknConfig "github.com/0KnowledgeNetwork/opt/genconfig/config"
)

const (
	basePort = 30000
	bindAddr = "127.0.0.1"
)

type katzenpost struct {
	baseDir   string
	outDir    string
	binSuffix string
	logLevel  string
	logWriter io.Writer

	ratchetNIKEScheme  string
	wireKEMScheme      string
	pkiSignatureScheme sign.Scheme
	sphinxGeometry     *geo.Geometry
	votingAuthConfigs  []*vConfig.Config
	authorities        map[[32]byte]*vConfig.Authority
	authIdentity       sign.PublicKey

	nodeConfigs    []*sConfig.Config
	basePort       uint16
	lastPort       uint16
	bindAddr       string
	nodeIdx        int
	clientIdx      int
	gatewayIdx     int
	serviceNodeIdx int
	hasPanda       bool
	hasProxy       bool
	noMixDecoy     bool
	debugConfig    *cConfig.Debug
}

type AuthById []*vConfig.Authority

func (a AuthById) Len() int           { return len(a) }
func (a AuthById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a AuthById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

type NodeById []*vConfig.Node

func (a NodeById) Len() int           { return len(a) }
func (a NodeById) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a NodeById) Less(i, j int) bool { return a[i].Identifier < a[j].Identifier }

func addressesFromURLs(addrs []string) map[string][]string {
	addresses := make(map[string][]string)
	for _, addr := range addrs {
		u, err := url.Parse(addr)
		if err != nil {
			continue
		}
		switch u.Scheme {
		case cpki.TransportTCP, cpki.TransportTCPv4, cpki.TransportTCPv6, cpki.TransportQUIC:
			if _, ok := addresses[u.Scheme]; !ok {
				addresses[u.Scheme] = make([]string, 0)
			}
			addresses[u.Scheme] = append(addresses[u.Scheme], u.String())
		default:
			continue
		}
	}
	return addresses
}

func (s *katzenpost) genClient2Cfg() error {
	log.Print("genClient2Cfg begin")
	os.Mkdir(filepath.Join(s.outDir, "client2"), 0700)
	cfg := new(cConfig2.Config)

	//cfg.ListenNetwork = "unixpacket"
	//cfg.ListenAddress = "@katzenpost"

	cfg.ListenNetwork = "tcp"
	cfg.ListenAddress = "localhost:64331"

	cfg.PKISignatureScheme = s.pkiSignatureScheme.Name()
	cfg.WireKEMScheme = s.wireKEMScheme
	cfg.SphinxGeometry = s.sphinxGeometry

	// Logging section.
	cfg.Logging = &cConfig2.Logging{File: "", Level: "DEBUG"}

	// UpstreamProxy section
	cfg.UpstreamProxy = &cConfig2.UpstreamProxy{Type: "none"}

	// VotingAuthority section

	peers := make([]*vConfig.Authority, 0)
	for _, peer := range s.authorities {
		peers = append(peers, peer)
	}

	sort.Sort(AuthById(peers))

	cfg.VotingAuthority = &cConfig2.VotingAuthority{Peers: peers}

	// Debug section
	cfg.Debug = &cConfig2.Debug{DisableDecoyTraffic: s.debugConfig.DisableDecoyTraffic}

	log.Print("before gathering providers")
	gateways := make([]*cConfig2.Gateway, 0)
	for i := 0; i < len(s.nodeConfigs); i++ {
		if s.nodeConfigs[i].Gateway == nil {
			continue
		}

		idPubKey := cfgIdKey(s.nodeConfigs[i], s.outDir)
		linkPubKey := cfgLinkKey(s.nodeConfigs[i], s.outDir, cfg.WireKEMScheme)

		gateway := &cConfig2.Gateway{
			PKISignatureScheme: s.pkiSignatureScheme.Name(),
			WireKEMScheme:      s.wireKEMScheme,
			Name:               s.nodeConfigs[i].Server.Identifier,
			IdentityKey:        idPubKey,
			LinkKey:            linkPubKey,
			Addresses:          s.nodeConfigs[i].Server.Addresses,
		}
		gateways = append(gateways, gateway)
	}
	if len(gateways) == 0 {
		log.Print("Note: 0 gateways")
	}
	log.Print("after gathering providers")
	cfg.PinnedGateways = &cConfig2.Gateways{
		Gateways: gateways,
	}

	log.Print("before save config")
	err := saveCfg(cfg, s.outDir)
	if err != nil {
		log.Printf("save config failure %s", err.Error())
		return err
	}
	log.Print("after save config")
	return nil
}

func (s *katzenpost) genClientCfg() error {
	os.Mkdir(filepath.Join(s.outDir, "client"), 0700)
	cfg := new(cConfig.Config)

	cfg.RatchetNIKEScheme = s.ratchetNIKEScheme
	cfg.WireKEMScheme = s.wireKEMScheme
	cfg.PKISignatureScheme = s.pkiSignatureScheme.Name()
	cfg.SphinxGeometry = s.sphinxGeometry

	s.clientIdx++

	// Logging section.
	cfg.Logging = &cConfig.Logging{File: "", Level: s.logLevel}

	// UpstreamProxy section
	cfg.UpstreamProxy = &cConfig.UpstreamProxy{Type: "none"}

	// VotingAuthority section

	peers := make([]*vConfig.Authority, 0)
	for _, peer := range s.authorities {
		peers = append(peers, peer)
	}

	sort.Sort(AuthById(peers))

	cfg.VotingAuthority = &cConfig.VotingAuthority{Peers: peers}

	// Debug section
	cfg.Debug = s.debugConfig
	err := saveCfg(cfg, s.outDir)
	if err != nil {
		return err
	}
	return nil
}

func write(f *os.File, str string, args ...interface{}) {
	str = fmt.Sprintf(str, args...)
	_, err := f.WriteString(str)

	if err != nil {
		log.Fatal(err)
	}
}

func (s *katzenpost) genNodeConfig(isGateway, isServiceNode bool, isVoting bool) error {
	const serverLogFile = "katzenpost.log"

	n := fmt.Sprintf("mix%d", s.nodeIdx+1)
	if isGateway {
		n = fmt.Sprintf("gateway%d", s.gatewayIdx+1)
	} else if isServiceNode {
		n = fmt.Sprintf("servicenode%d", s.serviceNodeIdx+1)
	}

	cfg := new(sConfig.Config)
	cfg.SphinxGeometry = s.sphinxGeometry

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.WireKEM = s.wireKEMScheme
	cfg.Server.PKISignatureScheme = s.pkiSignatureScheme.Name()
	cfg.Server.Identifier = n
	if isGateway {
		cfg.Server.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort), fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort+1),
			fmt.Sprintf("onion://thisisjustatestoniontoverifythatconfigandpkiworkproperly.onion:4242")}
		cfg.Server.BindAddresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort), fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort+1)}
		s.lastPort += 2
	} else {
		cfg.Server.Addresses = []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort)}
		s.lastPort += 1
	}
	cfg.Server.DataDir = filepath.Join(s.baseDir, n)

	os.Mkdir(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)

	cfg.Server.IsGatewayNode = isGateway
	cfg.Server.IsServiceNode = isServiceNode
	if isGateway {
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true
	}
	if isServiceNode {
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true
	}
	// Enable Metrics endpoint
	cfg.Server.MetricsAddress = fmt.Sprintf("127.0.0.1:%d", s.lastPort)
	s.lastPort += 1

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	cfg.Debug.SendDecoyTraffic = !s.noMixDecoy

	// PKI section.
	if isVoting {
		authorities := make([]*vConfig.Authority, 0, len(s.authorities))
		i := 0
		for _, auth := range s.authorities {
			authorities = append(authorities, auth)
			i += 1
		}

		sort.Sort(AuthById(authorities))
		cfg.PKI = &sConfig.PKI{
			Voting: &sConfig.Voting{
				Authorities: authorities,
			},
		}
	}

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = s.logLevel

	if isServiceNode {
		// Enable the thwack interface.
		s.serviceNodeIdx++

		// configure an entry provider or a spool storage provider
		cfg.ServiceNode = &sConfig.ServiceNode{}
		spoolCfg := &sConfig.CBORPluginKaetzchen{
			Capability:     "spool",
			Endpoint:       "+spool",
			Command:        s.baseDir + "/memspool" + s.binSuffix,
			MaxConcurrency: 1,
			Config: map[string]interface{}{
				"data_store": s.baseDir + "/" + cfg.Server.Identifier + "/memspool.storage",
				"log_dir":    s.baseDir + "/" + cfg.Server.Identifier,
			},
		}
		cfg.ServiceNode.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{spoolCfg}
		if !s.hasPanda {
			mapCfg := &sConfig.CBORPluginKaetzchen{
				Capability:     "pigeonhole",
				Endpoint:       "+pigeonhole",
				Command:        s.baseDir + "/pigeonhole" + s.binSuffix,
				MaxConcurrency: 1,
				Config: map[string]interface{}{
					"db":      s.baseDir + "/" + cfg.Server.Identifier + "/map.storage",
					"log_dir": s.baseDir + "/" + cfg.Server.Identifier,
				},
			}

			cfg.ServiceNode.CBORPluginKaetzchen = []*sConfig.CBORPluginKaetzchen{spoolCfg, mapCfg}
			if !s.hasPanda {
				pandaCfg := &sConfig.CBORPluginKaetzchen{
					Capability:     "panda",
					Endpoint:       "+panda",
					Command:        s.baseDir + "/panda_server" + s.binSuffix,
					MaxConcurrency: 1,
					Config: map[string]interface{}{
						"fileStore": s.baseDir + "/" + cfg.Server.Identifier + "/panda.storage",
						"log_dir":   s.baseDir + "/" + cfg.Server.Identifier,
						"log_level": s.logLevel,
					},
				}
				cfg.ServiceNode.CBORPluginKaetzchen = append(cfg.ServiceNode.CBORPluginKaetzchen, pandaCfg)
				s.hasPanda = true
			}

			// Add a single instance of a http proxy for a service listening on port 4242
			if !s.hasProxy {
				proxyCfg := &sConfig.CBORPluginKaetzchen{
					Capability:     "http",
					Endpoint:       "+http",
					Command:        s.baseDir + "/proxy_server" + s.binSuffix,
					MaxConcurrency: 1,
					Config: map[string]interface{}{
						// allow connections to localhost:4242
						"host":      "localhost:4242",
						"log_dir":   s.baseDir + "/" + cfg.Server.Identifier,
						"log_level": "DEBUG",
					},
				}
				cfg.ServiceNode.CBORPluginKaetzchen = append(cfg.ServiceNode.CBORPluginKaetzchen, proxyCfg)
				s.hasProxy = true
			}
			cfg.Debug.NumKaetzchenWorkers = 4
		}

		echoCfg := new(sConfig.Kaetzchen)
		echoCfg.Capability = "echo"
		echoCfg.Endpoint = "+echo"
		cfg.ServiceNode.Kaetzchen = append(cfg.ServiceNode.Kaetzchen, echoCfg)
		testdestCfg := new(sConfig.Kaetzchen)
		testdestCfg.Capability = "testdest"
		testdestCfg.Endpoint = "+testdest"
		cfg.ServiceNode.Kaetzchen = append(cfg.ServiceNode.Kaetzchen, testdestCfg)

	} else if isGateway {
		s.gatewayIdx++
		cfg.Gateway = &sConfig.Gateway{}
	} else {
		s.nodeIdx++
	}
	s.nodeConfigs = append(s.nodeConfigs, cfg)
	_ = cfgIdKey(cfg, s.outDir)
	_ = cfgLinkKey(cfg, s.outDir, s.wireKEMScheme)
	return cfg.FixupAndValidate()
}

func (s *katzenpost) genVotingAuthoritiesCfg(numAuthorities int, parameters *vConfig.Parameters, nrLayers int, wirekem string) error {

	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	s.authorities = make(map[[32]byte]*vConfig.Authority)
	for i := 1; i <= numAuthorities; i++ {
		cfg := new(vConfig.Config)
		cfg.SphinxGeometry = s.sphinxGeometry
		cfg.Server = &vConfig.Server{
			WireKEMScheme:      s.wireKEMScheme,
			PKISignatureScheme: s.pkiSignatureScheme.Name(),
			Identifier:         fmt.Sprintf("auth%d", i),
			Addresses:          []string{fmt.Sprintf("tcp://127.0.0.1:%d", s.lastPort)},
			DataDir:            filepath.Join(s.baseDir, fmt.Sprintf("auth%d", i)),
		}
		os.Mkdir(filepath.Join(s.outDir, cfg.Server.Identifier), 0700)
		s.lastPort += 1
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
			Level:   s.logLevel,
		}
		cfg.Parameters = parameters
		cfg.Debug = &vConfig.Debug{
			Layers:           nrLayers,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		idKey := cfgIdKey(cfg, s.outDir)
		linkKey := cfgLinkKey(cfg, s.outDir, wirekem)
		authority := &vConfig.Authority{
			Identifier:         fmt.Sprintf("auth%d", i),
			IdentityPublicKey:  idKey,
			LinkPublicKey:      linkKey,
			WireKEMScheme:      wirekem,
			PKISignatureScheme: s.pkiSignatureScheme.Name(),
			Addresses:          cfg.Server.Addresses,
		}
		s.authorities[hash.Sum256From(idKey)] = authority
	}

	// tell each authority about it's peers
	for i := 0; i < numAuthorities; i++ {
		peers := []*vConfig.Authority{}
		for _, peer := range s.authorities {
			peers = append(peers, peer)
		}
		sort.Sort(AuthById(peers))
		configs[i].Authorities = peers
	}
	s.votingAuthConfigs = configs
	return nil
}

func (s *katzenpost) genAuthorizedNodes() ([]*vConfig.Node, []*vConfig.Node, []*vConfig.Node, error) {
	mixes := []*vConfig.Node{}
	gateways := []*vConfig.Node{}
	serviceNodes := []*vConfig.Node{}
	for _, nodeCfg := range s.nodeConfigs {
		node := &vConfig.Node{
			Identifier:           nodeCfg.Server.Identifier,
			IdentityPublicKeyPem: filepath.Join("../", nodeCfg.Server.Identifier, "identity.public.pem"),
		}
		if nodeCfg.Server.IsGatewayNode {
			gateways = append(gateways, node)
		} else if nodeCfg.Server.IsServiceNode {
			serviceNodes = append(serviceNodes, node)
		} else {
			mixes = append(mixes, node)
		}
	}
	sort.Sort(NodeById(mixes))
	sort.Sort(NodeById(gateways))
	sort.Sort(NodeById(serviceNodes))

	return gateways, serviceNodes, mixes, nil
}

func main() {
	var err error

	// tmp hack: these are here to minimize other changes to the original...
	nrLayers := new(int)
	nrNodes := new(int)
	nrGateways := new(int)
	nrServiceNodes := new(int)
	voting := new(bool)
	nrVoting := new(int)
	omitTopology := new(bool)

	inputNetworkInfo := flag.String("input", "network.yml", "Path to network info file")
	cfgType := flag.String("type", "", "Type of config to generate: mix, gateway, servicenode, client1, client")
	baseDir := flag.String("dir-base", "", "Path to use as installation directory")
	basePort := flag.Int("port", basePort, "First port number to use")
	bindAddr := flag.String("address", bindAddr, "Address to bind to")
	outDir := flag.String("dir-out", "", "Path to write files to")
	logLevel := flag.String("log-level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")

	flag.Parse()

	// Read the network info file
	data, err := os.ReadFile(*inputNetworkInfo)
	if err != nil {
		log.Fatalf("Error reading file: %v\n", err)
	}
	var networkInfo zknConfig.NetworkInfo
	err = yaml.Unmarshal(data, &networkInfo)
	if err != nil {
		log.Fatalf("Error decoding YAML: %v\n", err)
	}

	*nrLayers = networkInfo.KpMiscTopologyLayers
	*omitTopology = true                                          // "Dynamic topology (omit fixed topology definition)"
	wirekem := &networkInfo.KpConfigWirekem                       // "Name of the KEM Scheme to be used with wire protocol"
	kem := &networkInfo.KpConfigKem                               // "Name of the KEM Scheme to be used with Sphinx"
	nike := &networkInfo.KpConfigNike                             // "Name of the NIKE Scheme to be used with Sphinx"
	ratchetNike := &networkInfo.KpConfigRatchetNike               // "Name of the NIKE Scheme to be used with the doubleratchet"
	pkiSignatureScheme := &networkInfo.KpConfigPkiSignatureScheme // "PKI Signature Scheme to be used"
	UserForwardPayloadLength := &networkInfo.KpConfigUserForwardPayloadLength

	if *wirekem == "" {
		log.Fatal("wire KEM must be set")
	}

	if *kem == "" && *nike == "" {
		log.Fatal("either nike or kem must be set")
	}
	if *kem != "" && *nike != "" {
		log.Fatal("nike and kem flags cannot both be set")
	}

	if *ratchetNike == "" {
		log.Fatal("ratchetNike must be set")
	}

	if *pkiSignatureScheme == "" {
		log.Fatal("pkiSignatureScheme must be set")
	}

	// generate config for a single node of the given type, each with its own authority
	*nrNodes = 0
	*nrGateways = 0
	*nrServiceNodes = 0
	*nrVoting = 1
	*voting = true
	switch *cfgType {
	case "":
		log.Fatal("type must be set")
	case "mix":
		*nrNodes = 1
	case "gateway":
		*nrGateways = 1
	case "servicenode":
		*nrServiceNodes = 1
	case "client", "client1":
		*voting = false
	default:
		log.Fatal("invalid type")
	}

	parameters := &vConfig.Parameters{
		SendRatePerMinute: networkInfo.KpConfigSendRatePerMinute,
		Mu:                networkInfo.KpConfigMu,
		MuMaxDelay:        networkInfo.KpConfigMuMaxDelay,
		LambdaP:           networkInfo.KpConfigLambdaP,
		LambdaPMaxDelay:   networkInfo.KpConfigLambdaPMaxDelay,
		LambdaL:           networkInfo.KpConfigLambdaL,
		LambdaLMaxDelay:   networkInfo.KpConfigLambdaLMaxDelay,
		LambdaD:           networkInfo.KpConfigLambdaD,
		LambdaDMaxDelay:   networkInfo.KpConfigLambdaDMaxDelay,
		LambdaM:           networkInfo.KpConfigLambdaM,
		LambdaMMaxDelay:   networkInfo.KpConfigLambdaMMaxDelay,
		LambdaGMaxDelay:   networkInfo.KpConfigLambdaGMaxDelay,
	}

	s := &katzenpost{}

	s.ratchetNIKEScheme = *ratchetNike

	s.wireKEMScheme = *wirekem
	if kemschemes.ByName(*wirekem) == nil {
		log.Fatal("invalid wire KEM scheme")
	}

	s.baseDir = *baseDir
	s.outDir = *outDir
	s.binSuffix = ""
	s.basePort = uint16(*basePort)
	s.lastPort = s.basePort + 1
	s.bindAddr = *bindAddr
	s.logLevel = *logLevel
	s.debugConfig = &cConfig.Debug{
		DisableDecoyTraffic:         networkInfo.KpClientDebugDisableDecoyTraffic,
		SessionDialTimeout:          networkInfo.KpClientDebugSessionDialTimeout,
		InitialMaxPKIRetrievalDelay: networkInfo.KpClientDebugInitialMaxPKIDelay,
		PollingInterval:             networkInfo.KpClientDebugPollingInterval,
	}
	s.noMixDecoy = !networkInfo.KpDebugSendDecoyTraffic

	nrHops := *nrLayers + 2

	if *nike != "" {
		nikeScheme := schemes.ByName(*nike)
		if nikeScheme == nil {
			log.Fatalf("failed to resolve nike scheme %s", *nike)
		}
		s.sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			*UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if *kem != "" {
		kemScheme := kemschemes.ByName(*kem)
		if kemScheme == nil {
			log.Fatalf("failed to resolve kem scheme %s", *kem)
		}
		s.sphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			*UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if *pkiSignatureScheme != "" {
		signScheme := signSchemes.ByName(*pkiSignatureScheme)
		if signScheme == nil {
			log.Fatalf("failed to resolve pki signature scheme %s", *pkiSignatureScheme)
		}
		s.pkiSignatureScheme = signScheme
	}

	os.Mkdir(s.outDir, 0700)
	os.Mkdir(filepath.Join(s.outDir, s.baseDir), 0700)

	if *voting {
		// Generate the voting authority configurations
		err := s.genVotingAuthoritiesCfg(*nrVoting, parameters, *nrLayers, *wirekem)
		if err != nil {
			log.Fatalf("getVotingAuthoritiesCfg failed: %s", err)
		}
	}

	// Generate the gateway configs.
	for i := 0; i < *nrGateways; i++ {
		if err = s.genNodeConfig(true, false, *voting); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}
	// Generate the service node configs.
	for i := 0; i < *nrServiceNodes; i++ {
		if err = s.genNodeConfig(false, true, *voting); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the mix node configs.
	for i := 0; i < *nrNodes; i++ {
		if err = s.genNodeConfig(false, false, *voting); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}
	// Generate the authority config
	if *voting {
		gateways, serviceNodes, mixes, err := s.genAuthorizedNodes()
		if err != nil {
			panic(err)
		}
		for _, vCfg := range s.votingAuthConfigs {
			vCfg.Mixes = mixes
			vCfg.GatewayNodes = gateways
			vCfg.ServiceNodes = serviceNodes
			if *omitTopology == false {
				vCfg.Topology = new(vConfig.Topology)
				vCfg.Topology.Layers = make([]vConfig.Layer, 0)
				for i := 0; i < *nrLayers; i++ {
					vCfg.Topology.Layers = append(vCfg.Topology.Layers, *new(vConfig.Layer))
					vCfg.Topology.Layers[i].Nodes = make([]vConfig.Node, 0)
				}
				for j := range mixes {
					layer := j % *nrLayers
					vCfg.Topology.Layers[layer].Nodes = append(vCfg.Topology.Layers[layer].Nodes, *mixes[j])
				}
			}
		}
		for _, vCfg := range s.votingAuthConfigs {
			if err := saveCfg(vCfg, *outDir); err != nil {
				log.Fatalf("Failed to saveCfg of authority with %s", err)
			}
		}
	}
	// write the mixes keys and configs to disk
	for _, v := range s.nodeConfigs {
		if err := saveCfg(v, *outDir); err != nil {
			log.Fatalf("saveCfg failure: %s", err)
		}
	}

	if *cfgType == "client1" {
		err = s.genClientCfg()
		if err != nil {
			log.Fatalf("%s", err)
		}
	}

	if *cfgType == "client" {
		err = s.genClient2Cfg()
		if err != nil {
			log.Fatalf("%s", err)
		}
	}
}

func identifier(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return "client"
	case *cConfig2.Config:
		return "client2"
	case *sConfig.Config:
		return cfg.(*sConfig.Config).Server.Identifier
	case *vConfig.Config:
		return cfg.(*vConfig.Config).Server.Identifier
	default:
		log.Fatalf("identifier() passed unexpected type")
		return ""
	}
}

func toml_name(cfg interface{}) string {
	switch cfg.(type) {
	case *cConfig.Config:
		return "client"
	case *cConfig2.Config:
		return "client"
	case *sConfig.Config:
		return "katzenpost"
	case *vConfig.Config:
		return "authority"
	default:
		log.Fatalf("toml_name() passed unexpected type")
		return ""
	}
}

func saveCfg(cfg interface{}, outDir string) error {
	fileName := filepath.Join(outDir, identifier(cfg), fmt.Sprintf("%s.toml", toml_name(cfg)))
	log.Printf("writing %s", fileName)
	f, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("os.Create(%s) failed: %s", fileName, err)
	}
	defer f.Close()

	// Serialize the descriptor.
	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}

func cfgIdKey(cfg interface{}, outDir string) sign.PublicKey {
	var priv, public string
	var pkiSignatureScheme string
	switch cfg.(type) {
	case *sConfig.Config:
		priv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "identity.private.pem")
		public = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "identity.public.pem")
		pkiSignatureScheme = cfg.(*sConfig.Config).Server.PKISignatureScheme
	case *vConfig.Config:
		priv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "identity.private.pem")
		public = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "identity.public.pem")
		pkiSignatureScheme = cfg.(*vConfig.Config).Server.PKISignatureScheme
	default:
		panic("wrong type")
	}

	scheme := signSchemes.ByName(pkiSignatureScheme)
	if scheme == nil {
		panic("invalid PKI signature scheme " + pkiSignatureScheme)
	}

	idPubKey, err := signpem.FromPublicPEMFile(public, scheme)
	if err == nil {
		return idPubKey
	}
	idPubKey, idKey, err := scheme.GenerateKey()
	log.Printf("writing %s", priv)
	signpem.PrivateKeyToFile(priv, idKey)
	log.Printf("writing %s", public)
	signpem.PublicKeyToFile(public, idPubKey)
	return idPubKey
}

func cfgLinkKey(cfg interface{}, outDir string, kemScheme string) kem.PublicKey {
	var linkpriv string
	var linkpublic string

	switch cfg.(type) {
	case *sConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "link.private.pem")
		linkpublic = filepath.Join(outDir, cfg.(*sConfig.Config).Server.Identifier, "link.public.pem")
	case *vConfig.Config:
		linkpriv = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "link.private.pem")
		linkpublic = filepath.Join(outDir, cfg.(*vConfig.Config).Server.Identifier, "link.public.pem")
	default:
		panic("wrong type")
	}

	linkPubKey, linkPrivKey, err := kemschemes.ByName(kemScheme).GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	log.Printf("writing %s", linkpriv)
	err = kempem.PrivateKeyToFile(linkpriv, linkPrivKey)
	if err != nil {
		panic(err)
	}
	log.Printf("writing %s", linkpublic)
	err = kempem.PublicKeyToFile(linkpublic, linkPubKey)
	if err != nil {
		panic(err)
	}
	return linkPubKey
}
