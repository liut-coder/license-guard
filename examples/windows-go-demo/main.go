package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"license-guard/sdk/go/licenseguard"
)

func main() {
	mode := flag.String("mode", "activate", "activate, verify, heartbeat, deactivate, public-key, or local")
	endpoint := flag.String("endpoint", "http://127.0.0.1:8090/v1", "License Guard client API endpoint")
	appID := flag.String("app-id", "app_nax_desktop_prod", "License Guard app id")
	version := flag.String("version", "1.4.2", "application version")
	licenseKey := flag.String("license", "LG-DEMO-2026-WINDOWS", "license key for activation")
	binaryHash := flag.String("binary-hash", "demo-main-binary-sha256", "main binary hash override for local demo")
	signer := flag.String("signer", "demo-signer-thumbprint", "signer thumbprint override for local demo")
	publicKey := flag.String("public-key", "", "base64 Ed25519 public key for local cached token validation")
	flag.Parse()

	client, err := licenseguard.NewClient(licenseguard.Options{
		AppID:              *appID,
		Endpoint:           *endpoint,
		PublicKey:          *publicKey,
		AppVersion:         *version,
		BinaryHashOverride: *binaryHash,
		SignerThumbprint:   *signer,
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	switch *mode {
	case "public-key":
		key, err := client.FetchPublicKey(ctx)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(key)
	case "activate":
		result, err := client.Activate(ctx, *licenseKey)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(result)
		if !result.Allowed {
			os.Exit(2)
		}
		fmt.Printf("export.enabled: %v\n", client.IsAllowed("export.enabled"))
	case "verify":
		result, err := client.Verify(ctx)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(result)
		if !result.Allowed {
			os.Exit(2)
		}
	case "heartbeat":
		if err := client.Heartbeat(ctx); err != nil {
			log.Fatal(err)
		}
		fmt.Println("heartbeat ok")
	case "deactivate":
		if err := client.Deactivate(ctx); err != nil {
			log.Fatal(err)
		}
		fmt.Println("deactivate ok")
	case "local":
		auth, err := client.CachedAuthorization()
		if err != nil {
			log.Fatal(err)
		}
		printJSON(auth)
		if !auth.Allowed {
			os.Exit(2)
		}
		fmt.Printf("export.enabled: %v\n", client.IsAllowed("export.enabled"))
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

func printJSON(value any) {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(payload))
}
