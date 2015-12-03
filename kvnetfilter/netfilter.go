package kvnetfilter

import (
	"github.com/42wim/registrator-work/bridge"
	consulapi "github.com/hashicorp/consul/api"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	bridge.Register(new(Factory), "kvnetfilter")
}

type Factory struct{}

func (f *Factory) New(uri *url.URL) bridge.RegistryAdapter {
	// init consul
	config := consulapi.DefaultConfig()
	if uri.Host != "" {
		config.Address = uri.Host
	}
	client, err := consulapi.NewClient(config)
	if err != nil {
		log.Fatal("consulkv: ", uri.Scheme)
	}

	params := strings.Split(uri.Path, "/")
	if len(params) != 5 {
		log.Fatal("no correct scheme", len(params), params)
	}

	kvpath := params[1]
	aclpath := params[2]
	// init netfilter
	chain := params[3]
	set := params[4]

	FirewalldInit()
	if firewalldRunning {
		OnReloaded(func() { iptablesInit(chain, set) })
	}
	ipsetInit(set)
	iptablesInit(chain, set)

	return &NetfilterAdapter{Chain: chain, Set: set, client: client, path: kvpath, aclpath: aclpath}

}

type NetfilterAdapter struct {
	Chain   string
	Set     string
	client  *consulapi.Client
	path    string
	aclpath string
}

func (r *NetfilterAdapter) Ping() error {
	return nil
}

func (r *NetfilterAdapter) Register(service *bridge.Service) error {
	if strings.Contains(service.IP, ":") {
		err := r.kvRegister(service)
		if err != nil {
			return err
		}
		var srcRanges []string
		// traverse every tag
		for _, tag := range service.Tags {
			srcRanges = append(srcRanges, r.kvFindACL(service.Name+"/"+tag+"/")...)
		}
		// service too
		srcRanges = append(srcRanges, r.kvFindACL(service.Name+"/")...)

		if len(srcRanges) > 0 {
			log.Println("would allow ", srcRanges)
			for _, src := range srcRanges {
				res := strings.Split(src, "#")
				srcip := res[0]
				ts, _ := strconv.Atoi(res[1])
				// exclude ourself and stale info
				if int(time.Now().Unix())-ts < service.TTL && service.IP != srcip {
					ipsetSrcDst("add", r.Set, srcip, service.IP, service.Origin.PortType, strconv.Itoa(service.Port), strconv.Itoa(service.TTL))
				} else {
					log.Println("stale service found, not adding", srcip, service.TTL, ts, time.Now().Unix())
				}
			}
		}
	}
	return nil
}

func (r *NetfilterAdapter) Deregister(service *bridge.Service) error {
	if strings.Contains(service.IP, ":") {
		var srcRanges []string
		// traverse every tag
		for _, tag := range service.Tags {
			srcRanges = append(srcRanges, r.kvFindACL(service.Name+"/"+tag+"/")...)
		}
		// service too
		srcRanges = append(srcRanges, r.kvFindACL(service.Name+"/")...)

		if len(srcRanges) > 0 {
			log.Println("would allow ", srcRanges)
			for _, src := range srcRanges {
				res := strings.Split(src, "#")
				srcip := res[0]
				ipsetSrcDst("del", r.Set, srcip, service.IP, service.Origin.PortType, strconv.Itoa(service.Port), "")
			}
		}
		// deregister after netfilter removal
		err := r.kvDeregister(service)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *NetfilterAdapter) Refresh(service *bridge.Service) error {
	return r.Register(service)
}

func (r *NetfilterAdapter) kvRegister(service *bridge.Service) error {
	path := r.path[1:] + "/" + service.Name + "/" + service.ID
	_, err := r.client.KV().Put(&consulapi.KVPair{Key: path, Value: []byte(service.IP + "#" + strconv.Itoa(int(time.Now().Unix())))}, nil)
	if err != nil {
		log.Println("consulkv: failed to register service:", err)
	}
	for _, tag := range service.Tags {
		path = r.path[1:] + "/" + service.Name + "/" + tag + "/" + service.ID
		_, err := r.client.KV().Put(&consulapi.KVPair{Key: path, Value: []byte(service.IP + "#" + strconv.Itoa(int(time.Now().Unix())))}, nil)
		if err != nil {
			log.Println("consulkv: failed to register service:", err)
		}
	}
	return err
}

func (r *NetfilterAdapter) kvDeregister(service *bridge.Service) error {
	if !strings.Contains(service.IP, ":") {
		return nil
	}
	path := r.path[1:] + "/" + service.Name + "/" + service.ID
	_, err := r.client.KV().Delete(path, nil)
	if err != nil {
		log.Println("consulkv: failed to deregister service:", err)
	}
	for _, tag := range service.Tags {
		path = r.path[1:] + "/" + service.Name + "/" + tag + "/" + service.ID
		_, err := r.client.KV().Delete(path, nil)
		if err != nil {
			log.Println("consulkv: failed to deregister service:", err)
		}
	}
	return err
}

func (r *NetfilterAdapter) kvFindACL(key string) []string {
	var acls []string
	url := "/" + r.aclpath + "/" + key
	log.Println("looking for ACL in ", url)
	kps, _, _ := r.client.KV().List(url, nil)
	for _, kp := range kps {
		if len(kp.Value) > 0 {
			log.Println("keys to search ", string(kp.Value))
			rkps, _, _ := r.client.KV().List(string(kp.Value), nil)
			for _, rkp := range rkps {
				log.Print("found acl: ", string(rkp.Value))
				acls = append(acls, string(rkp.Value))
			}
		}
	}
	return acls
}
