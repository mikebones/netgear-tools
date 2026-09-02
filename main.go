package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"netgear-tools/internal/provider"
)

// version is set by the build (ldflags -X main.version=...) when packaged
// for release. Left as "dev" for local filesystem-mirror use.
var version = "dev"

func main() {
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// Matches the local filesystem mirror convention used by this repo's
		// sibling local providers.
		Address: "local/mikebones/netgear",
	})
	// Not deferred: log.Fatal below would skip it. Sessions held on the
	// devices are only released by asking, so this has to run on both paths.
	provider.Cleanup()

	if err != nil {
		log.Fatal(err.Error())
	}
}
