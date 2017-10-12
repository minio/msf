package cmd

import (
	"log"
	"os"

	"github.com/minio/mfs/pkg/logger"
)

func handleSignals() {
	// Custom exit function
	exit := func(state bool) {
		if state {
			os.Exit(0)
		}

		os.Exit(1)
	}

	stopProcess := func() bool {
		var err error
		err = globalHTTPServer.Shutdown()
		logger.ErrorIf(err, "Unable to shutdown http server")

		return (err == nil)
	}

	for {
		select {
		case err := <-globalHTTPServerErrorCh:
			logger.ErrorIf(err, "http server exited abnormally")
			exit(err == nil)
		case osSignal := <-globalOSSignalCh:
			log.Printf("Exiting on signal %v\n", osSignal)
			exit(stopProcess())
		}
	}
}
