package netfilter

import (
	"github.com/42wim/registrator-work/bridge"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	bridge.Register(new(Factory), "netfilter")
}

type Factory struct{}

func (f *Factory) New(uri *url.URL) bridge.RegistryAdapter {
	var chain, set string
	if uri.Host != "" {
		chain = uri.Host
		set = strings.Replace(uri.Path, "/", "", -1)
	} else {
		chain = "FORWARD_direct"
		set = "containerports"
	}
	ipsetInit(set)

	if chain != "-" {
		FirewalldInit()
		if firewalldRunning {
			OnReloaded(func() { iptablesInit(chain, set) })
		}
		iptablesInit(chain, set)
	}
	return &NetfilterAdapter{Chain: chain, Set: set}
}

type NetfilterAdapter struct {
	Chain string
	Set   string
}

func (r *NetfilterAdapter) Ping() error {
	return nil
}

func (r *NetfilterAdapter) SetsForHost(service *bridge.Service) []string {
	name := service.Name
	tags := service.Tags
	port := strconv.Itoa(service.Port)

	sets := []string{
		// default set
		r.Set,
		// service_name
		name,
		// service_name/service_port
		name + "/" + port,
	}

	for _, t := range tags {
		// service_name/service_tag
		sets = append(sets, name+"/"+t)
		// service_name/service_tag/service_port
		sets = append(sets, name+"/"+t+"/"+port)
	}

	return sets
}

func (r *NetfilterAdapter) Register(service *bridge.Service) error {
	if strings.Contains(service.IP, ":") {
		for _, set := range r.SetsForHost(service) {
			err := ipsetHost("add", set, service.IP, service.Origin.PortType, strconv.Itoa(service.Port), strconv.Itoa(service.TTL))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *NetfilterAdapter) Deregister(service *bridge.Service) error {
	if strings.Contains(service.IP, ":") {
		for _, set := range r.SetsForHost(service) {
			err := ipsetHost("del", set, service.IP, service.Origin.PortType, strconv.Itoa(service.Port), "")
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *NetfilterAdapter) Refresh(service *bridge.Service) error {
	return r.Register(service)
}

func (r *NetfilterAdapter) Services() ([]*bridge.Service, error) {
	return []*bridge.Service{}, nil
}
