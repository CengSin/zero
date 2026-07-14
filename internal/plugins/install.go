package plugins

// Distribution: install a plugin from a git URL or a local path into a plugins
// directory, with the manifest validated and a content hash recorded in a
// lockfile (plugins.lock). Install copies the plugin tree verbatim but NEVER
// executes any of it — installed plugins still go through normal Stage 09
// activation with permission gating before any tool can run.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Gitlawb/zero/internal/fscopy"
)

// manifestFileName is the plugin manifest filename, matching the loader.
const manifestFileName = "plugin.json"

// LockFileName maps an installed plugin id to its source and content hash.
const LockFileName = "plugins.lock"

// ErrNameClash is returned when an install would overwrite a plugin already
// installed from a DIFFERENT source, unless InstallOptions.Force is set.
var ErrNameClash = errors.New("a different plugin with that id is already installed")

// GitRunner fetches the plugin at source into destination. The default runner
// shallow-clones with the system git (inheriting the process environment, so
// proxy/egress settings are honored). It is injectable so tests never hit the
// network. A runner must only fetch — it must never execute fetched content.
type GitRunner func(ctx context.Context, destination string, source string) error

// InstallOptions configures a single plugin install.
type InstallOptions struct {
	// Source is a git URL or a local filesystem path to a plugin directory (one
	// that contains a plugin.json, or whose tree contains exactly one).
	Source string
	// Dir is the plugins directory to install into (typically the user plugins
	// root from ResolveRoots).
	Dir string
	// Force allows overwriting a plugin installed from a different source.
	Force bool
	// GitRunner overrides the fetch implementation. When nil, a git source is
	// shallow-cloned with the system git.
	GitRunner GitRunner
}

// InstallResult reports what an install did.
type InstallResult struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	ManifestPath string `json:"manifestPath"`
	Hash         string `json:"hash"`
	Source       string `json:"source"`
	Updated      bool   `json:"updated"`
	PreviousHash string `json:"previousHash,omitempty"`
}

// LockEntry records the source and content hash for one installed plugin.
type LockEntry struct {
	Source string `json:"source"`
	Hash   string `json:"hash"`
}

// Install fetches the plugin at options.Source, validates its manifest, copies
// the plugin tree into options.Dir/<id>/, and records a content hash (over the
// manifest bytes) in the lockfile. Fetched content is never executed.
func Install(ctx context.Context, options InstallOptions) (InstallResult, error) {
	source := strings.TrimSpace(options.Source)
	if source == "" {
		return InstallResult{}, errors.New("a plugin source (git URL or path) is required")
	}
	dir := strings.TrimSpace(options.Dir)
	if dir == "" {
		return InstallResult{}, errors.New("a plugins directory is required")
	}
	// Canonicalize a local source so clash detection keys off the resolved path,
	// not the spelling the user typed (relative vs absolute, symlinked vs not).
	source = canonicalSource(source)

	fetchDir, cleanup, err := fetchSource(ctx, source, options.GitRunner)
	if err != nil {
		return InstallResult{}, err
	}
	defer cleanup()

	pluginDir, err := locatePluginDir(fetchDir)
	if err != nil {
		return InstallResult{}, err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return InstallResult{}, fmt.Errorf("create plugins dir: %w", err)
	}
	// Converge any interrupted replace from a prior install into this root before
	// we create a new staging dir; otherwise a kill between the two renames of a
	// previous swap would leave target absent with the old tree stranded under a
	// deterministic backup name — this restores it and sweeps any orphaned
	// staging before a new install can clash with either.
	if err := RecoverPending(dir); err != nil {
		return InstallResult{}, err
	}
	// Stage the new tree outside the scanned plugins root, but still on the SAME
	// filesystem (the root's parent directory), so the swap into place is a
	// single atomic rename and concurrent loaders cannot discover a partial
	// tree. We copy FIRST and only clear the previous install AFTER the copy
	// succeeds, so a failed copy (full disk, permission denied) leaves the
	// previously installed plugin and its lockfile entry completely intact
	// instead of wiping them and stranding the lockfile pointing at a deleted
	// directory.
	// Copy the whole plugin tree (entry scripts, prompts, skills) so the installed
	// plugin is runnable through activation. Copy DATA only — never execute it.
	stagingParent := filepath.Dir(filepath.Clean(dir))
	staging, err := os.MkdirTemp(stagingParent, ".zero-plugin-install-")
	if err != nil {
		return InstallResult{}, fmt.Errorf("create staging dir: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := fscopy.CopyTree(pluginDir, staging); err != nil {
		return InstallResult{}, fmt.Errorf("copy plugin: %w", err)
	}

	// Validate the manifest from the STAGING copy — not from the source — so
	// the parsed plugin and install target describe the bytes that will actually
	// be installed. This also catches source manifests that were symlinks skipped
	// by CopyTree.
	stagingManifest := filepath.Join(staging, manifestFileName)
	data, err := os.ReadFile(stagingManifest)
	if err != nil {
		return InstallResult{}, fmt.Errorf("staged %s missing (source may contain only symlinks): %w", manifestFileName, err)
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return InstallResult{}, fmt.Errorf("parse staged %s: %w", manifestFileName, err)
	}

	// Validate against the same schema the loader uses. The install target id is
	// derived from the staged, validated manifest id, so it is safe as a directory
	// name.
	parsed, err := ParseManifest(raw, ParseManifestOptions{
		Source:       SourceUser,
		Root:         dir,
		PluginDir:    staging,
		ManifestPath: stagingManifest,
	})
	if err != nil {
		return InstallResult{}, fmt.Errorf("invalid plugin manifest: %w", err)
	}
	id := parsed.ID

	// Hash the staging tree — the actual installed content — not the source.
	// This ensures the recorded hash matches what is on disk after the swap, so
	// a change to any installed file (a tool script, prompt, or bundled skill)
	// is reflected in the lock hash and reported as an update.
	hash, err := fscopy.HashTree(staging)
	if err != nil {
		return InstallResult{}, fmt.Errorf("hash plugin: %w", err)
	}

	lock, err := ReadLock(dir)
	if err != nil {
		return InstallResult{}, err
	}
	previous, existed := lock[id]
	if existed && previous.Source != source && !options.Force {
		return InstallResult{}, fmt.Errorf("%w: %q is installed from %s (use --force to overwrite)", ErrNameClash, id, previous.Source)
	}

	target := filepath.Join(dir, id)
	if err := swapStagedPluginIntoPlace(staging, target); err != nil {
		return InstallResult{}, err
	}
	committed = true

	lock[id] = LockEntry{Source: source, Hash: hash}
	if err := writeLock(dir, lock); err != nil {
		return InstallResult{}, err
	}

	result := InstallResult{
		ID:           id,
		Name:         parsed.Name,
		Version:      parsed.Version,
		ManifestPath: filepath.Join(target, manifestFileName),
		Hash:         hash,
		Source:       source,
	}
	if existed {
		result.Updated = previous.Hash != hash
		result.PreviousHash = previous.Hash
	}
	return result, nil
}

// copyAndSwapIntoPlace copies src into a temp staging dir on the same filesystem
// as target (typically outside the scanned plugin root), then atomically swaps
// the staging dir into place at target. The copy happens before the previous
// install is touched, so a copy failure leaves the existing target (if any)
// intact. On success the old install (if any) is removed; on a swap failure
// it is rolled back into place, so an install never ends with the plugin gone
// but the lockfile still pointing at it.
func copyAndSwapIntoPlace(src, dirParent, target string) error {
	staging, err := os.MkdirTemp(dirParent, ".zero-plugin-install-")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	if err := fscopy.CopyTree(src, staging); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("copy plugin: %w", err)
	}
	return swapStagedPluginIntoPlace(staging, target)
}

// swapPrefix marks a staged-replacement backup directory. A swap moves the
// existing target aside under a name derived from this prefix plus the plugin
// id; the deterministic suffix lets RecoverPending recognize a backup a crashed
// swap left behind and either complete (commit) or undo (rollback) it.
const swapPrefix = ".zero-plugin-replace-"

// swapBackupPath is the deterministic path swapStagedPluginIntoPlace stashes
// the existing install at, and the path RecoverPending must look for it under.
// It is a sibling of target in the install dir's PARENT (the same dir staging
// is created in), never inside target — a move-into-self would be EINVAL — and
// it lives where RecoverPending scans (filepath.Dir(dir)), so a stranded backup
// is always recoverable. Both sides go through this helper so a crash between
// the two renames is guaranteed convergent: the backup can never be written
// where recovery does not look.
func swapBackupPath(target string) string {
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Clean(target))), swapPrefix+filepath.Base(target))
}

// swapStagedPluginIntoPlace atomically renames a prepared staging dir into the
// final target. The staging tree must already be fully copied and validated by
// the caller.
//
// The replace is a two-rename sequence (stash old → move new in → drop old),
// not a single atomic syscall. To stay recoverable across a kill or power loss
// between those renames, the existing install is stashed under a DETERMINISTIC
// name (swapPrefix + id) rather than staging+".old", and recoverSwap runs first
// to converge any interrupted prior replace for this target to a known state.
// That makes the window between the two renames idempotent to replay: a crash
// after step 1 leaves target absent with the old tree stranded under a known
// name, and the next recoverSwap (Install or Load) restores it.
func swapStagedPluginIntoPlace(staging, target string) error {
	// backup lives in the install dir's PARENT (the same dir staging was created
	// in), not inside target and not inside the install dir. It must be a SIBLING
	// of target so the stash rename (target → backup) is a same-directory rename,
	// never a move-into-self (EINVAL); and it must live where RecoverPending
	// scans, which is filepath.Dir(dir) — i.e. this parent. The parent is on the
	// same filesystem as target, so the rename stays atomic.
	backup := swapBackupPath(target)
	if err := recoverSwap(backup, target); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	// No existing install: a plain rename is already atomic.
	if _, err := os.Stat(target); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("stat target: %w", err)
		}
		if err := os.Rename(staging, target); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("install plugin: %w", err)
		}
		return nil
	}
	// Existing install: move it aside, swap the new tree in, then drop the old
	// one — only after the swap succeeds, so a failed rename rolls the previous
	// install back into place and the failure stays non-destructive.
	if err := os.Rename(target, backup); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("stash previous plugin: %w", err)
	}
	if err := os.Rename(staging, target); err != nil {
		// Roll the previous install back so the failure leaves the old plugin intact.
		_ = os.Rename(backup, target)
		_ = os.RemoveAll(staging)
		return fmt.Errorf("install plugin: %w", err)
	}
	return os.RemoveAll(backup)
}

// recoverSwap converges an interrupted replace of target to a known state. It
// is idempotent — safe to run any number of times, and safe after a crash of
// its own — because it branches purely on which of {backup, target} currently
// exist:
//
//	backup absent                 → nothing to recover
//	target present + backup present → crashed after the new tree landed; commit by dropping backup
//	target absent  + backup present → crashed after stashing the old tree but before the new one landed; roll the old tree back to target
//
// backup must be the deterministic name swapStagedPluginIntoPlace uses.
func recoverSwap(backup, target string) error {
	if _, err := os.Stat(backup); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat swap backup: %w", err)
	}
	// Backup present — the old tree (or the new one, if the crash happened post-land) lives there.
	if _, err := os.Stat(target); err == nil {
		// New tree already landed; the backup is the now-superseded old tree.
		return os.RemoveAll(backup)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat target: %w", err)
	}
	// Target absent, backup present: the old tree was stashed but the new one
	// never landed. Restore it so the canonical install (and the lockfile entry
	// pointing at it) is whole again.
	if err := os.Rename(backup, target); err != nil {
		return fmt.Errorf("restore previous plugin: %w", err)
	}
	return nil
}

// RecoverPending converges every interrupted plugin replace under dir to a
// known state, and sweeps orphaned staging dirs a crashed install left behind.
// It is safe and no-op when nothing is pending. Call it before discovering the
// plugins root (Load) and at the start of any install into the same root, so a
// kill or power loss between the two renames of a prior install never leaves the
// canonical install absent with the old tree stranded under a random name and
// the lockfile pointing at a missing target.
func RecoverPending(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	parent := filepath.Dir(filepath.Clean(dir))
	entries, err := os.ReadDir(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("scan install parent: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, swapPrefix):
			id := strings.TrimPrefix(name, swapPrefix)
			if !validInstallID(id) {
				continue
			}
			if err := recoverSwap(filepath.Join(parent, name), filepath.Join(dir, id)); err != nil {
				return err
			}
		case strings.HasPrefix(name, stagingPrefix):
			// Orphaned staging from a crashed install: no transaction to
			// converge, just reclaim the space.
			_ = os.RemoveAll(filepath.Join(parent, name))
		}
	}
	return nil
}

// stagingPrefix marks a transient staging directory created during install.
const stagingPrefix = ".zero-plugin-install-"

// Remove deletes an installed plugin directory and its lockfile entry. It errors
// if the named plugin is not present in either the dir or the lockfile.
func Remove(dir string, id string) error {
	dir = strings.TrimSpace(dir)
	id = strings.TrimSpace(id)
	if dir == "" || id == "" {
		return errors.New("a plugins directory and plugin id are required")
	}
	if !validInstallID(id) {
		return fmt.Errorf("invalid plugin id %q", id)
	}

	lock, err := ReadLock(dir)
	if err != nil {
		return err
	}
	_, locked := lock[id]
	target := filepath.Join(dir, id)
	_, statErr := os.Stat(target)
	present := statErr == nil
	if !locked && !present {
		return fmt.Errorf("plugin %q is not installed", id)
	}
	if present {
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("remove plugin dir: %w", err)
		}
	}
	if locked {
		delete(lock, id)
		if err := writeLock(dir, lock); err != nil {
			return err
		}
	}
	return nil
}

// ReadLock loads the plugins lockfile from dir. A missing lockfile yields an
// empty map with no error.
func ReadLock(dir string) (map[string]LockEntry, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return map[string]LockEntry{}, nil
	}
	data, err := os.ReadFile(filepath.Join(dir, LockFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]LockEntry{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", LockFileName, err)
	}
	entries := map[string]LockEntry{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", LockFileName, err)
	}
	return entries, nil
}

func writeLock(dir string, entries map[string]LockEntry) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create plugins dir: %w", err)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", LockFileName, err)
	}
	if err := os.WriteFile(filepath.Join(dir, LockFileName), append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", LockFileName, err)
	}
	return nil
}

// fetchSource resolves a source into a local directory. A local path is used in
// place; a git URL is shallow-cloned into a temp dir via the runner.
func fetchSource(ctx context.Context, source string, runner GitRunner) (string, func(), error) {
	if isLocalPath(source) {
		info, err := os.Stat(source)
		if err != nil {
			return "", func() {}, fmt.Errorf("read source: %w", err)
		}
		if !info.IsDir() {
			return "", func() {}, fmt.Errorf("source must be a directory: %s", source)
		}
		abs, err := filepath.Abs(source)
		if err != nil {
			return "", func() {}, err
		}
		return abs, func() {}, nil
	}

	if runner == nil {
		runner = defaultGitRunner
	}
	temp, err := os.MkdirTemp("", "zero-plugin-fetch-")
	if err != nil {
		return "", func() {}, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(temp) }
	if err := runner(ctx, temp, source); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("fetch %s: %w", source, err)
	}
	return temp, cleanup, nil
}

// defaultGitRunner shallow-clones source into destination. exec.CommandContext
// inherits the process environment, so proxy/egress settings are honored;
// GIT_TERMINAL_PROMPT=0 prevents a credential prompt from blocking. Cloning only
// fetches; it never executes repository content.
func defaultGitRunner(ctx context.Context, destination string, source string) error {
	command := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--", source, destination)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// locatePluginDir finds the directory holding plugin.json within root: the root
// itself, or exactly one immediate subdirectory.
func locatePluginDir(root string) (string, error) {
	if fileExists(filepath.Join(root, manifestFileName)) {
		return root, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("scan source: %w", err)
	}
	matches := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(root, entry.Name())
		if fileExists(filepath.Join(candidate, manifestFileName)) {
			matches = append(matches, candidate)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no %s found in source", manifestFileName)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("source contains multiple plugins (%d); install one at a time", len(matches))
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// canonicalSource normalizes a local filesystem source to an absolute,
// symlink-evaluated path so a re-install via a different spelling of the same
// directory is recognized as the same source. Remote sources (git URLs) are
// returned unchanged. On any resolution error the input is returned as-is so a
// non-existent local path still surfaces its real error later in fetchSource.
func canonicalSource(source string) string {
	if !isLocalPath(source) {
		return source
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return source
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// isLocalPath reports whether source is a local filesystem path rather than a
// remote URL. URLs (scheme://… or scp-style host:path) and git shorthand are
// remote.
func isLocalPath(source string) bool {
	if source == "" {
		return false
	}
	if strings.HasPrefix(source, ".") || strings.HasPrefix(source, "/") || strings.HasPrefix(source, "~") {
		return true
	}
	if filepath.IsAbs(source) {
		return true
	}
	if hasURLScheme(source) {
		return false
	}
	if idx := strings.Index(source, ":"); idx > 0 {
		host := source[:idx]
		if strings.Contains(host, "@") {
			return false
		}
		if len(host) == 1 {
			return true // drive letter
		}
		if strings.Contains(host, ".") {
			return false // hostname
		}
	}
	return true
}

func hasURLScheme(source string) bool {
	for _, scheme := range []string{"http://", "https://", "git://", "ssh://", "git+ssh://", "ftp://", "ftps://", "file://"} {
		if strings.HasPrefix(strings.ToLower(source), scheme) {
			return true
		}
	}
	return false
}

// validInstallID guards a plugin id used as a directory component. Manifest ids
// already match pluginIDPattern, but Remove takes an id directly from the user.
func validInstallID(id string) bool {
	if !pluginIDPattern.MatchString(id) {
		return false
	}
	return id == filepath.Base(id) && !strings.ContainsAny(id, `/\`) && !strings.Contains(id, "..")
}
