// Copyright 2019 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/networkservicemesh/networkservicemesh/controlplane/api/networkservice"
	"github.com/networkservicemesh/networkservicemesh/pkg/tools"
	"github.com/networkservicemesh/networkservicemesh/sdk/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/cisco-app-networking/nsm-nse/pkg/metrics"
	"github.com/cisco-app-networking/nsm-nse/pkg/nseconfig"
	"github.com/cisco-app-networking/nsm-nse/pkg/universal-cnf/ucnf"
	"github.com/cisco-app-networking/nsm-nse/pkg/universal-cnf/vppagent"
)

const (
	metricsPortEnv     = "METRICS_PORT"
	metricsPath        = "/metrics"
	metricsPortDefault = "2112"
)

const (
	defaultConfigPath   = "/etc/universal-cnf/config.yaml"
	defaultPluginModule = ""
)

// Flags holds the command line flags as supplied with the binary invocation
type Flags struct {
	ConfigPath string
	Verify     bool
}

// Process will parse the command line flags and init the structure members
func (mf *Flags) Process() {
	flag.StringVar(&mf.ConfigPath, "file", defaultConfigPath, " full path to the configuration file")
	flag.BoolVar(&mf.Verify, "verify", false, "only verify the configuration, don't run")
	flag.Parse()
}

type vL3CompositeEndpoint struct {
}

func (e vL3CompositeEndpoint) AddCompositeEndpoints(nsConfig *common.NSConfiguration, ucnfEndpoint *nseconfig.Endpoint) *[]networkservice.NetworkServiceServer {

	logrus.WithFields(logrus.Fields{
		"prefixPool":         nsConfig.IPAddress,
		"nsConfig.IPAddress": nsConfig.IPAddress,
	}).Infof("Creating vL3 IPAM endpoint")

	var nsRemoteIpList []string
	nsRemoteIpListStr, ok := os.LookupEnv("NSM_REMOTE_NS_IP_LIST")
	if ok {
		nsRemoteIpList = strings.Split(nsRemoteIpListStr, ",")
	}
	compositeEndpoints := []networkservice.NetworkServiceServer{
		newVL3ConnectComposite(nsConfig, nsConfig.IPAddress,
			&vppagent.UniversalCNFVPPAgentBackend{}, nsRemoteIpList, func() string {
				return ucnfEndpoint.NseName
			}, ucnfEndpoint.VL3.IPAM.DefaultPrefixPool, ucnfEndpoint.VL3.IPAM.ServerAddress, ucnfEndpoint.NseControl.ConnectivityDomain),
	}

	return &compositeEndpoints
}

// exported the symbol named "CompositeEndpointPlugin"

func main() {
	// Capture signals to cleanup before exiting
	logrus.Info("STARTING ENDPOINT")
	c := tools.NewOSSignalChannel()

	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.TraceLevel)
	logrus.SetReportCaller(true)

	mainFlags := &Flags{}
	mainFlags.Process()

	InitializeMetrics()

	// Capture signals to cleanup before exiting
	prometheus.NewBuildInfoCollector()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vl3 := vL3CompositeEndpoint{}
	ucnfNse := ucnf.NewUcnfNse(mainFlags.ConfigPath, mainFlags.Verify, &vppagent.UniversalCNFVPPAgentBackend{}, vl3, ctx)
	logrus.Info("endpoint started")

	defer ucnfNse.Cleanup()
	<-c
}

func InitializeMetrics() {
	metricsPort := os.Getenv(metricsPortEnv)
	if metricsPort == "" {
		metricsPort = metricsPortDefault
	}
	addr := fmt.Sprintf("0.0.0.0:%v", metricsPort)
	logrus.WithField("path", metricsPath).Infof("Serving metrics on: %v", addr)
	metrics.ServeMetrics(addr, metricsPath)
}

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{
		EnvironmentOverrideColors: true,
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			const modulePath = "github.com/cisco-app-networking/nsm-nse"
			call := strings.TrimPrefix(frame.Function, modulePath)
			function = fmt.Sprintf("%s()", strings.TrimPrefix(call, "/"))
			_, file = filepath.Split(frame.File)
			file = fmt.Sprintf("%s:%d", file, frame.Line)
			return
		},
	})
	logrus.AddHook(silenceHook)
	go silenceHook.silenceLoop()
}

func newLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetReportCaller(logrus.StandardLogger().ReportCaller)
	logrus.AddHook(silenceHook)
	return logger
}

var silenceHook = &SilenceHook{
	resetChan: make(chan struct{}, 1),
}

type SilenceHook struct {
	resetChan chan struct{}
	//sync.Mutex
}

func (s *SilenceHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (s *SilenceHook) Fire(entry *logrus.Entry) error {
	//s.Lock()
	//defer s.Unlock()
	select {
	case s.resetChan <- struct{}{}:
	default:
	}
	return nil
}

func (s *SilenceHook) silenceLoop() {
	t := time.NewTimer(0)
	<-t.C
	for {
		select {
		case <-t.C:
			logrus.Debugf("----------------------------------------------------------------------------------")
		case <-s.resetChan:
			if !t.Stop() {
				<-t.C
			}
			t.Reset(time.Second)
		}
	}
}
