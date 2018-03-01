package main

import (
	_ "github.com/42wim/registrator-work/consul"
	_ "github.com/42wim/registrator-work/consulkv"
	_ "github.com/42wim/registrator-work/etcd"
	_ "github.com/42wim/registrator-work/skydns2"
	_ "github.com/42wim/registrator-work/kvnetfilter"
	_ "github.com/42wim/registrator-work/netfilter"
)
