// Command runtime-release is the Agent Runtime release pipeline: it cuts,
// signs, and verifies the approved release material after an image build.
//
// A cut takes a built image digest (or a lifecycle decision) and regenerates
// everything that must move together: the runtime manifest documents, the
// release catalog, the definitions that pin each release, the definition
// catalog, provenance and image-signature evidence, and the signed catalog
// attestations. Verification runs the same ingestion the service runs at
// startup, so material this tool accepts is material the control plane will.
//
//	runtime-release cut       -image <unit>=sha256:... -source-commit <sha> ...
//	runtime-release lifecycle -unit <unit> -state revoked|disabled|active ...
//	runtime-release verify    -releases <dir> -definitions <dir> ...
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

const timestampLayout = trust.Timestamp

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "runtime-release:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("a subcommand is required: cut, lifecycle, or verify")
	}
	switch arguments[0] {
	case "cut":
		return runCutCommand(arguments[1:], false)
	case "lifecycle":
		return runCutCommand(arguments[1:], true)
	case "verify":
		return runVerifyCommand(arguments[1:])
	default:
		return fmt.Errorf("unknown subcommand %q: use cut, lifecycle, or verify", arguments[0])
	}
}

// imageAssignments collects repeated -image unit=digest flags.
type imageAssignments map[string]string

func (a imageAssignments) String() string { return fmt.Sprintf("%d images", len(a)) }

func (a imageAssignments) Set(value string) error {
	unit, digest, found := strings.Cut(value, "=")
	if !found || unit == "" || digest == "" {
		return fmt.Errorf("expected <runtimeUnitId>=<sha256 digest>")
	}
	if _, duplicate := a[unit]; duplicate {
		return fmt.Errorf("unit %s is assigned twice", unit)
	}
	a[unit] = digest
	return nil
}

// pathList collects repeated file-path flags.
type pathList []string

func (l *pathList) String() string { return strings.Join(*l, ",") }

func (l *pathList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

// storeFlags are the flags every subcommand shares.
type storeFlags struct {
	contractRoot   *string
	releasesDir    *string
	definitionsDir *string
	now            *string
}

func declareStoreFlags(set *flag.FlagSet) storeFlags {
	return storeFlags{
		contractRoot:   set.String("contract-root", ".", "service root carrying the pinned contract intake"),
		releasesDir:    set.String("releases", "internal/runtimes/releases", "approved release store to read"),
		definitionsDir: set.String("definitions", "internal/agent/definitions", "approved definition store to read"),
		now:            set.String("now", "", "evaluation instant, RFC 3339 (default: the current time)"),
	}
}

func (f storeFlags) instant() (time.Time, error) {
	if *f.now == "" {
		return time.Now().UTC(), nil
	}
	instant, err := time.Parse(time.RFC3339, *f.now)
	if err != nil {
		return time.Time{}, fmt.Errorf("-now must be RFC 3339: %w", err)
	}
	return instant.UTC(), nil
}

// signingFlags are the flags of every subcommand that seals attestations.
type signingFlags struct {
	seedPath           *string
	ephemeral          *bool
	keyID              *string
	issuer             *string
	definitionSeedPath *string
	definitionKeyID    *string
	definitionIssuer   *string
	validity           *time.Duration
}

func declareSigningFlags(set *flag.FlagSet) signingFlags {
	return signingFlags{
		seedPath:           set.String("signing-seed", "", "file carrying the base64url Ed25519 release signing seed"),
		ephemeral:          set.Bool("ephemeral", false, "generate a fresh signing key and publish its seed with the cut (pipeline verification only)"),
		keyID:              set.String("key-id", releaseKeyID, "release signing key identity"),
		issuer:             set.String("issuer", releaseIssuer, "release statement issuer"),
		definitionSeedPath: set.String("definition-signing-seed", "", "file carrying the definition catalog signing seed (default: the release seed)"),
		definitionKeyID:    set.String("definition-key-id", definitionKeyID, "definition catalog signing key identity"),
		definitionIssuer:   set.String("definition-issuer", definitionIssuer, "definition catalog statement issuer"),
		validity:           set.Duration("validity", 720*time.Hour, "attestation and trust-root validity window"),
	}
}

func (f signingFlags) authorities() (release, definition signingAuthority, ephemeralSeed []byte, err error) {
	switch {
	case *f.ephemeral && *f.seedPath != "":
		return signingAuthority{}, signingAuthority{}, nil, fmt.Errorf("-ephemeral and -signing-seed are mutually exclusive")
	case *f.ephemeral:
		release, ephemeralSeed, err = ephemeralAuthority(*f.keyID, *f.issuer)
		if err != nil {
			return signingAuthority{}, signingAuthority{}, nil, err
		}
	case *f.seedPath != "":
		release, err = authorityFromSeedFile(*f.seedPath, *f.keyID, *f.issuer)
		if err != nil {
			return signingAuthority{}, signingAuthority{}, nil, err
		}
	default:
		return signingAuthority{}, signingAuthority{}, nil, fmt.Errorf("a signing seed is required: -signing-seed <file>, or -ephemeral for pipeline verification")
	}
	if *f.definitionSeedPath != "" {
		definition, err = authorityFromSeedFile(*f.definitionSeedPath, *f.definitionKeyID, *f.definitionIssuer)
		if err != nil {
			return signingAuthority{}, signingAuthority{}, nil, err
		}
	} else {
		definition = signingAuthority{key: release.key, keyID: *f.definitionKeyID, issuer: *f.definitionIssuer}
	}
	return release, definition, ephemeralSeed, nil
}

// runCutCommand parses and runs a cut. A lifecycle change is a cut that
// rewrites lifecycle state instead of image identity: the cascade — manifest
// digests, catalogs, definition pins, attestations — is the same, which is why
// both subcommands share this path.
func runCutCommand(arguments []string, lifecycle bool) error {
	name := "cut"
	if lifecycle {
		name = "lifecycle"
	}
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	store := declareStoreFlags(set)
	signing := declareSigningFlags(set)
	images := imageAssignments{}
	sourceCommit := set.String("source-commit", "", "full commit the images were built from")
	builder := set.String("builder", "local-release", "identity of the builder, recorded in provenance")
	outDir := set.String("out", "", "directory receiving the cut store, evidence, and attestations")
	inPlace := set.Bool("in-place", false, "rewrite the source stores instead of copying into -out")
	var unit, state, reasonCode *string
	if lifecycle {
		unit = set.String("unit", "", "runtime unit whose lifecycle changes")
		state = set.String("state", "", "new lifecycle state: active, revoked, or disabled")
		reasonCode = set.String("reason-code", "", "stable reason code recorded with a revocation or disable")
	} else {
		set.Var(images, "image", "built image as <runtimeUnitId>=<sha256 digest> (repeatable)")
	}
	if err := set.Parse(arguments); err != nil {
		return err
	}
	var change *lifecycleChange
	if lifecycle {
		if *unit == "" || *state == "" {
			return fmt.Errorf("lifecycle requires -unit and -state")
		}
		change = &lifecycleChange{unit: *unit, state: *state, reasonCode: *reasonCode}
	}
	now, err := store.instant()
	if err != nil {
		return err
	}
	release, definition, ephemeralSeed, err := signing.authorities()
	if err != nil {
		return err
	}
	return runCut(cutRequest{
		contractRoot:   *store.contractRoot,
		releasesDir:    *store.releasesDir,
		definitionsDir: *store.definitionsDir,
		outDir:         *outDir,
		inPlace:        *inPlace,
		images:         images,
		sourceCommit:   *sourceCommit,
		builder:        *builder,
		lifecycle:      change,
		release:        release,
		definition:     definition,
		ephemeralSeed:  ephemeralSeed,
		now:            now,
		validity:       *signing.validity,
	})
}

func runVerifyCommand(arguments []string) error {
	set := flag.NewFlagSet("verify", flag.ContinueOnError)
	store := declareStoreFlags(set)
	trustRoot := set.String("trust-root", "", "operator trust root that must attest the catalogs")
	attestation := set.String("attestation", "", "release catalog attestation envelope")
	definitionAttestation := set.String("definition-attestation", "", "definition catalog attestation envelope")
	deployments := pathList{}
	set.Var(&deployments, "deployment", "rendered deployment material to scan for unresolved placeholders and unpinned images (repeatable)")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	now, err := store.instant()
	if err != nil {
		return err
	}
	request := verifyRequest{
		contractRoot:              *store.contractRoot,
		releasesDir:               *store.releasesDir,
		definitionsDir:            *store.definitionsDir,
		trustRootPath:             *trustRoot,
		attestationPath:           *attestation,
		definitionAttestationPath: *definitionAttestation,
		deployments:               deployments,
		now:                       now,
	}
	if err := runVerify(request); err != nil {
		return err
	}
	fmt.Println("release material verified")
	return nil
}
