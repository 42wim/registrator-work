package kvnetfilter

import (
	"log"
	"os/exec"
	"strings"
	"syscall"
)

const (
	ip6tablesPath = "/usr/sbin/ip6tables"
	ipsetPath     = "/usr/sbin/ipset"
)

func checkTestError(err error) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case err.(*exec.ExitError).Sys().(syscall.WaitStatus).ExitStatus() == 1:
		return false, nil
	default:
		return false, err
	}
}

func iptablesRun(ipcmd string) error {
	args := strings.Fields(ipcmd)
	if firewalldRunning && !strings.HasPrefix(ipcmd, "-t") {
		Passthrough(args)
	} else {
		cmd := exec.Cmd{Path: ip6tablesPath, Args: append([]string{ip6tablesPath}, args...)}
		if err := cmd.Run(); err != nil {
			return err.(*exec.ExitError)
		}
	}
	return nil
}

func ipsetRun(ipcmd string) error {
	args := strings.Fields(ipcmd)
	cmd := exec.Cmd{Path: ipsetPath, Args: append([]string{ipsetPath}, args...)}
	if err := cmd.Run(); err != nil {
		return err.(*exec.ExitError)
	}
	return nil
}

func ipsetSrcDst(command string, set string, srcip string, dstip string, proto string, port string, timeout string) error {
	cmd := "-! " + command + " " + set + " " + dstip + "," + proto + ":" + port + "," + srcip
	if timeout != "" {
		cmd = cmd + " timeout " + timeout
	}

	err := ipsetRun(cmd)
	if err != nil {
		return err
	}
	return nil
}

func iptablesInit(chain string, set string) error {
	exists, err := checkTestError(iptablesRun("-t filter -C " + chain + " -o docker0 -m set --match-set " + set + " dst,dst,src -j ACCEPT --wait"))
	if err != nil {
		return err
	}
	if !exists {
		iptablesRun("-A " + chain + " -o docker0 -m set --match-set " + set + " dst,dst,src -j ACCEPT --wait")
	}
	exists, err = checkTestError(iptablesRun("-t filter -C " + chain + " -o docker0 -j DROP --wait"))
	if err != nil {
		return err
	}
	if !exists {
		iptablesRun("-A " + chain + " -o docker0 -j DROP --wait")
	}

	// allow outgoing container traffic
	exists, err = checkTestError(iptablesRun("-t filter -C " + chain + " -i docker0 -j ACCEPT --wait"))
	if err != nil {
		return err
	}
	if !exists {
		iptablesRun("-A " + chain + " -i docker0 -j ACCEPT --wait")
	}

	return nil
}

func ipsetInit(set string) error {
	err := ipsetInitAndFlushWithHash(set, "ip,port,net")
	return err
}

func ipsetInitWithHash(set string, hash string) error {
	err := ipsetRun("-! create " + set + " hash:" + hash + " family inet6 counters timeout 0")
	if err != nil {
		log.Println("ipsetHost() could not create ipset: ", set)
		log.Println("Error: ", err)
		return err
	}
	return nil
}

func ipsetInitAndFlushWithHash(set string, hash string) error {
	err := ipsetInitWithHash(set, hash)
	if err != nil {
		return err
	}
	err = ipsetRun("-! flush " + set)
	if err != nil {
		return err
	}
	return nil
}
