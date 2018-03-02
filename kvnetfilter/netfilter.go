package kvnetfilter

import (
	"github.com/42wim/registrator-work/bridge"
	consulapi "github.com/hashicorp/consul/api"
	"log"
	"net/url"
	"path"
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
		for k, _ := range service.Tags {
			service.Tags[k] = path.Clean(service.Tags[k])
		}
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
		srcRanges = append(srcRanges, r.kvFindACL(service.Name+"/_all/")...)

		// look into FIREWALL metadata
		for key, v := range service.Attrs {
			if strings.HasPrefix(key, "FIREWALL") {
				// if we match the fwtag
				if "firewall_"+strconv.Itoa(service.Port) == strings.ToLower(key) {
					// split our comma separated value
					entries := strings.Split(v, ",")
					for _, entry := range entries {
						// parse the entry (is it a service or a group)
						srcRanges = append(srcRanges, r.parseFWConfig(entry)...)
					}
				}
				// if we have a firewall key without a tag, we must add it to everything
				if key == "FIREWALL" {
					entries := strings.Split(v, ",")
					for _, entry := range entries {
						// look up a service
						srcRanges = append(srcRanges, r.parseFWConfig(entry)...)
					}
				}
			}
		}

		// no results, use fallback
		if len(srcRanges) == 0 {
			srcRanges = append(srcRanges, r.kvFindACL("/_fallback/")...)
		}

		if len(srcRanges) > 0 {
			for _, src := range srcRanges {
				res := strings.Split(src, "#")
				if len(res) != 2 {
					log.Println("ERROR incorrect value: ", src)
					continue
				}
				srcip := res[0]
				ts, _ := strconv.Atoi(res[1])
				// exclude ourself and stale info
				if int(time.Now().Unix())-ts < service.TTL && service.IP != srcip {
					ipsetSrcDst("add", r.Set, srcip, service.IP, service.Origin.PortType, strconv.Itoa(service.Port), strconv.Itoa(service.TTL))
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
		srcRanges = append(srcRanges, r.kvFindACL(service.Name+"/_all/")...)

		// no results, use fallback
		if len(srcRanges) == 0 {
			srcRanges = append(srcRanges, r.kvFindACL("/_fallback/")...)
		}

		if len(srcRanges) > 0 {
			for _, src := range srcRanges {
				res := strings.Split(src, "#")
				if len(res) != 2 {
					log.Println("ERROR incorrect value: ", src)
					continue
				}
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
	var path string
	var err error
	// only register in /service.Name when tags are empty
	if len(service.Tags) == 0 {
		path = r.path + "/" + service.Name + "/" + service.ID
		_, err = r.client.KV().Put(&consulapi.KVPair{Key: path, Value: []byte(service.IP + "#" + strconv.Itoa(int(time.Now().Unix())))}, nil)
		if err != nil {
			log.Println("consulkv: failed to register service:", err)
		}
		return err
	}

	for _, tag := range service.Tags {
		path = r.path + "/" + service.Name + "/" + tag + "/" + service.ID
		_, err = r.client.KV().Put(&consulapi.KVPair{Key: path, Value: []byte(service.IP + "#" + strconv.Itoa(int(time.Now().Unix())))}, nil)
		if err != nil {
			log.Println("consulkv: failed to register service:", err)
		}
	}
	return err
}

func (r *NetfilterAdapter) kvDeregister(service *bridge.Service) error {
	var path string
	var err error
	if len(service.Tags) == 0 {
		path = r.path + "/" + service.Name + "/" + service.ID
		_, err = r.client.KV().Delete(path, nil)
		if err != nil {
			log.Println("consulkv: failed to deregister service:", err)
		}
		return err
	}

	for _, tag := range service.Tags {
		path = r.path + "/" + service.Name + "/" + tag + "/" + service.ID
		_, err = r.client.KV().Delete(path, nil)
		if err != nil {
			log.Println("consulkv: failed to deregister service:", err)
		}
	}
	return err
}

func (r *NetfilterAdapter) kvFindACL(key string) []string {
	var acls []string
	url := "/" + r.aclpath + "/" + key
	kps, _, _ := r.client.KV().List(url, nil)
	for _, kp := range kps {
		if len(kp.Value) > 0 {
			// if ipv6 address, add
			if strings.Contains(string(kp.Value), ":") {
				acls = append(acls, string(kp.Value))
				continue
			}
			rkps, _, _ := r.client.KV().List(string(kp.Value), nil)
			for _, rkp := range rkps {
				acls = append(acls, string(rkp.Value))
			}
		}
	}
	return acls
}

func (r *NetfilterAdapter) parseFWConfig(entry string) []string {
	var srcRanges []string
	// look up a service
	if strings.HasPrefix(entry, "s/") {
		svc := strings.Replace(entry, "s/", "", 1)
		// ../netfilter-auto/svc/
		srcRanges = append(srcRanges, r.kvFindACL("../"+r.path+"/"+svc+"/")...)
		// if we have a tag search that too
	}
	// lookup a group
	if strings.HasPrefix(entry, "g/") {
		svc := strings.Replace(entry, "g/", "", 1)
		// ../netfilter-auto/svc/
		srcRanges = append(srcRanges, r.kvFindACL("_groups/"+svc+"/")...)
		// if we have a tag search that too
	}
	return srcRanges
}

func (r *NetfilterAdapter) Services() ([]*bridge.Service, error) {
	return []*bridge.Service{}, nil
}
