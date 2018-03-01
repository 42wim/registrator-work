package main

import (
	_ "github.com/jovandeginste/registrator-work/consul"
	_ "github.com/jovandeginste/registrator-work/consulkv"
	_ "github.com/jovandeginste/registrator-work/etcd"
	_ "github.com/jovandeginste/registrator-work/skydns2"
	_ "github.com/jovandeginste/registrator-work/kvnetfilter"
	_ "github.com/jovandeginste/registrator-work/netfilter"
)
