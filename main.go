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
	if err != nil {
		log.Fatal(err.Error())
	}
}
