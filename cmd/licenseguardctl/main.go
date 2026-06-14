package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) < 2 || args[0] != "release" || args[1] != "publish" {
		return fmt.Errorf("usage: licenseguardctl release publish [flags]")
	}
	return runReleasePublish(ctx, args[2:])
}

func runReleasePublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("release publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	server := fs.String("server", envOrDefault("LICENSE_GUARD_ADMIN_URL", ""), "License Guard server URL, for example https://license.example")
	adminToken := fs.String("admin-token", os.Getenv("LICENSE_GUARD_ADMIN_TOKEN"), "admin bearer token")
	adminAccount := fs.String("admin-account", os.Getenv("LICENSE_GUARD_ADMIN_ACCOUNT"), "admin account used when admin-token is empty")
	adminPassword := fs.String("admin-password", os.Getenv("LICENSE_GUARD_ADMIN_PASSWORD"), "admin password used when admin-token is empty")
	appID := fs.String("app-id", "", "app id")
	platform := fs.String("platform", "windows", "release platform")
	version := fs.String("version", "", "app version")
	buildNumber := fs.Int("build-number", 0, "monotonic build number")
	channel := fs.String("channel", "production", "release channel")
	status := fs.String("status", "active", "release status")
	mainBinary := fs.String("main-binary", "", "path to the signed main binary")
	mainBinaryHash := fs.String("main-binary-hash", "", "signed main binary sha256 override")
	signerThumbprint := fs.String("signer-thumbprint", "", "code signing certificate thumbprint")
	packageFile := fs.String("package", "", "path to the installer or distribution package")
	packageSHA256 := fs.String("package-sha256", "", "package sha256 override")
	resourceManifestHash := fs.String("resource-manifest-hash", "", "optional resource manifest hash")
	downloadURL := fs.String("download-url", "", "release download URL")
	releaseNotes := fs.String("release-notes", "", "release notes text")
	releaseNotesFile := fs.String("release-notes-file", "", "release notes file")
	mandatory := fs.Bool("mandatory", false, "force this update")
	minSupportedVersion := fs.String("min-supported-version", "", "minimum supported version")
	rolloutPercent := fs.Int("rollout-percent", 100, "rollout percent 0-100")
	dryRun := fs.Bool("dry-run", false, "print payload without publishing")

	if err := fs.Parse(args); err != nil {
		return err
	}

	payload, err := buildReleasePayload(releaseInput{
		appID:                *appID,
		platform:             *platform,
		version:              *version,
		buildNumber:          *buildNumber,
		channel:              *channel,
		status:               *status,
		mainBinary:           *mainBinary,
		mainBinaryHash:       *mainBinaryHash,
		signerThumbprint:     *signerThumbprint,
		packageFile:          *packageFile,
		packageSHA256:        *packageSHA256,
		resourceManifestHash: *resourceManifestHash,
		downloadURL:          *downloadURL,
		releaseNotes:         *releaseNotes,
		releaseNotesFile:     *releaseNotesFile,
		mandatory:            *mandatory,
		minSupportedVersion:  *minSupportedVersion,
		rolloutPercent:       *rolloutPercent,
	})
	if err != nil {
		return err
	}

	if *dryRun {
		return writeJSON(os.Stdout, payload)
	}

	baseURL := normalizeServerURL(*server)
	if baseURL == "" {
		return errors.New("server URL is required")
	}
	token := strings.TrimSpace(*adminToken)
	if token == "" {
		var err error
		token, err = loginAdmin(ctx, baseURL, strings.TrimSpace(*adminAccount), strings.TrimSpace(*adminPassword))
		if err != nil {
			return err
		}
	}

	response, err := postAdminJSON(ctx, baseURL, token, "/admin/apps/"+url.PathEscape(payload.AppID)+"/releases", payload)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "published release %s %s build %d\n", payload.AppID, payload.Version, payload.BuildNumber)
	return writeJSON(os.Stdout, response)
}

type releaseInput struct {
	appID                string
	platform             string
	version              string
	buildNumber          int
	channel              string
	status               string
	mainBinary           string
	mainBinaryHash       string
	signerThumbprint     string
	packageFile          string
	packageSHA256        string
	resourceManifestHash string
	downloadURL          string
	releaseNotes         string
	releaseNotesFile     string
	mandatory            bool
	minSupportedVersion  string
	rolloutPercent       int
}

type releasePayload struct {
	AppID                string `json:"app_id"`
	Platform             string `json:"platform"`
	Version              string `json:"version"`
	BuildNumber          int    `json:"build_number"`
	Channel              string `json:"channel"`
	Status               string `json:"status"`
	SignerThumbprint     string `json:"signer_thumbprint"`
	MainBinaryHash       string `json:"main_binary_hash"`
	ResourceManifestHash string `json:"resource_manifest_hash,omitempty"`
	DownloadURL          string `json:"download_url"`
	PackageSHA256        string `json:"package_sha256"`
	Mandatory            bool   `json:"mandatory"`
	MinSupportedVersion  string `json:"min_supported_version,omitempty"`
	RolloutPercent       int    `json:"rollout_percent"`
	ReleaseNotes         string `json:"release_notes"`
}

func buildReleasePayload(input releaseInput) (releasePayload, error) {
	appID := strings.TrimSpace(input.appID)
	version := strings.TrimSpace(input.version)
	if appID == "" {
		return releasePayload{}, errors.New("app-id is required")
	}
	if version == "" {
		return releasePayload{}, errors.New("version is required")
	}
	if input.buildNumber <= 0 {
		return releasePayload{}, errors.New("build-number must be greater than zero")
	}

	mainHash, err := hashOrOverride(input.mainBinary, input.mainBinaryHash, "main-binary")
	if err != nil {
		return releasePayload{}, err
	}
	packageHash, err := hashOrOverride(input.packageFile, input.packageSHA256, "package")
	if err != nil {
		return releasePayload{}, err
	}
	notes, err := releaseNotesValue(input.releaseNotes, input.releaseNotesFile)
	if err != nil {
		return releasePayload{}, err
	}
	if strings.TrimSpace(input.signerThumbprint) == "" {
		return releasePayload{}, errors.New("signer-thumbprint is required")
	}
	if strings.TrimSpace(input.downloadURL) == "" {
		return releasePayload{}, errors.New("download-url is required")
	}
	rollout := input.rolloutPercent
	if rollout < 0 {
		rollout = 0
	}
	if rollout > 100 {
		rollout = 100
	}

	return releasePayload{
		AppID:                appID,
		Platform:             fallback(strings.TrimSpace(input.platform), "windows"),
		Version:              version,
		BuildNumber:          input.buildNumber,
		Channel:              fallback(strings.TrimSpace(input.channel), "production"),
		Status:               fallback(strings.TrimSpace(input.status), "active"),
		SignerThumbprint:     strings.TrimSpace(input.signerThumbprint),
		MainBinaryHash:       mainHash,
		ResourceManifestHash: strings.TrimSpace(input.resourceManifestHash),
		DownloadURL:          strings.TrimSpace(input.downloadURL),
		PackageSHA256:        packageHash,
		Mandatory:            input.mandatory,
		MinSupportedVersion:  strings.TrimSpace(input.minSupportedVersion),
		RolloutPercent:       rollout,
		ReleaseNotes:         notes,
	}, nil
}

func hashOrOverride(path string, override string, label string) (string, error) {
	value := strings.TrimSpace(override)
	if value != "" {
		return strings.ToLower(value), nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("%s path or %s-hash is required", label, label)
	}
	return fileSHA256Hex(path)
}

func fileSHA256Hex(path string) (string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func releaseNotesValue(value string, file string) (string, error) {
	if strings.TrimSpace(file) == "" {
		return strings.TrimSpace(value), nil
	}
	raw, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func loginAdmin(ctx context.Context, baseURL string, account string, password string) (string, error) {
	if account == "" || password == "" {
		return "", errors.New("admin-token or admin-account/admin-password is required")
	}
	var response struct {
		AdminToken string `json:"admin_token"`
	}
	if err := postJSON(ctx, baseURL+"/admin/login", "", map[string]string{"account": account, "password": password}, &response); err != nil {
		return "", err
	}
	if response.AdminToken == "" {
		return "", errors.New("admin login returned no token")
	}
	return response.AdminToken, nil
}

func postAdminJSON(ctx context.Context, baseURL string, token string, path string, payload any) (map[string]any, error) {
	var response map[string]any
	if err := postJSON(ctx, baseURL+path, token, payload, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func postJSON(ctx context.Context, target string, token string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("license guard returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func normalizeServerURL(value string) string {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	value = strings.TrimSuffix(value, "/v1")
	return strings.TrimRight(value, "/")
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func envOrDefault(key string, fallbackValue string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallbackValue
	}
	return value
}

func fallback(value string, fallbackValue string) string {
	if value == "" {
		return fallbackValue
	}
	return value
}
