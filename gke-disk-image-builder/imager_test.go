package imager

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteK8sManifests(t *testing.T) {
	// Create a temporary file
	tmpfile, err := os.CreateTemp("", "k8s-manifests-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up
	tmpfile.Close()

	req := Request{
		ImageName:            "test-image",
		ProjectName:          "test-project",
		K8sManifestsFilepath: tmpfile.Name(),
		K8sNamespace:         "test-namespace",
	}

	err = WriteK8sManifests(req)
	if err != nil {
		t.Fatalf("WriteK8sManifests failed: %v", err)
	}

	// Read the file content
	content, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	expected := `apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotContent
metadata:
  name: test-image-vsc
spec:
  deletionPolicy: Retain
  driver: pd.csi.storage.gke.io
  source:
    snapshotHandle: projects/test-project/global/images/test-image
  volumeSnapshotRef:
    name: test-image-vs
    namespace: test-namespace
---
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata:
  name: test-image-vs
  namespace: test-namespace
spec:
  source:
    volumeSnapshotContentName: test-image-vsc
`

	if string(content) != expected {
		t.Errorf("Unexpected content:\nGot:\n%s\nWant:\n%s", string(content), expected)
	}
}

func TestWriteK8sManifests_ParentDirDoesNotExist(t *testing.T) {
	req := Request{
		ImageName:            "test-image",
		ProjectName:          "test-project",
		K8sManifestsFilepath: "/nonexistent-dir-12345/manifests.yaml",
	}

	err := WriteK8sManifests(req)
	if err == nil {
		t.Fatal("WriteK8sManifests expected error but got nil")
	}

	expectedErrMsg := "parent directory \"/nonexistent-dir-12345\" does not exist"
	if !strings.Contains(err.Error(), expectedErrMsg) {
		t.Errorf("Expected error message containing %q, got %q", expectedErrMsg, err.Error())
	}
}

func TestBuildDiskStartupScriptValidImage(t *testing.T) {
	req := Request{
		ContainerImages:       []string{"ubuntu:latest", "gcr.io/test-project/test-image:v1"},
		StoreSnapshotCheckSum: true,
		ImagePullAuth:         None,
	}
	f, err := buildDiskStartupScript(req)
	if err != nil {
		t.Fatalf("buildDiskStartupScript failed: %v", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	contentBytes, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read generated script: %v", err)
	}
	content := string(contentBytes)
	expectedSuffix := "\n\nunpack true None 'ubuntu:latest' 'gcr.io/test-project/test-image:v1'"
	if !strings.HasSuffix(content, expectedSuffix) {
		t.Errorf("expected script to end with %q, but got %q", expectedSuffix, content)
	}
}

// TestBuildDiskStartupScriptShellInjectionNeutralized tests that shell command
// injection payloads in container image references are neutralized by being
// safely single-quoted.
func TestBuildDiskStartupScriptShellInjectionNeutralized(t *testing.T) {
	req := Request{
		JobName:               "test-job",
		ContainerImages:       []string{"ubuntu:latest;id>/tmp/PWNED;#"},
		StoreSnapshotCheckSum: true,
		ImagePullAuth:         None,
	}
	f, err := buildDiskStartupScript(req)
	if err != nil {
		t.Fatalf("buildDiskStartupScript failed: %v", err)
	}
	scriptPath := f.Name()
	f.Close()
	defer os.Remove(scriptPath)

	contentBytes, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read generated script: %v", err)
	}
	content := string(contentBytes)

	expectedSuffix := "\n\nunpack true None 'ubuntu:latest;id>/tmp/PWNED;#'"
	if !strings.HasSuffix(content, expectedSuffix) {
		t.Errorf("expected script to end with %q, but got %q", expectedSuffix, content)
	}

	lines := strings.Split(content, "\n")
	last := lines[len(lines)-1]

	// Part B: Execution check. Run the generated line under bash with unpack stubbed
	// and verify that `/tmp/PWNED` is NOT created.
	pwnedFile := "/tmp/PWNED"
	_ = os.Remove(pwnedFile) // ensure it doesn't exist beforehand
	defer os.Remove(pwnedFile)

	cmdStr := fmt.Sprintf("unpack() { :; }\n%s", last)
	cmd := exec.Command("bash", "-c", cmdStr)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to run shell execution check: %v", err)
	}

	if _, err := os.Stat(pwnedFile); !os.IsNotExist(err) {
		t.Fatalf("injection execution check failed: %s was created, meaning command injection succeeded!", pwnedFile)
	}
}

func TestProcessSnapshots(t *testing.T) {
	tests := []struct {
		name           string
		initialViews   string
		outputSubdir   string
		storeChecksums string
		wantMetadata   string
		wantLayer1Path string
		wantLayer2Path string
	}{
		{
			name:           "secondary_boot_disk_copy",
			initialViews:   "stale_view\n",
			outputSubdir:   "mnt/disks/container_layers",
			storeChecksums: "true",
			wantMetadata:   fmt.Sprintf("%s snapshots/1/fs %s\n%s snapshots/2/fs %s\n", chainID1, osReleaseDirMD5, chainID2, nginxDirMD5),
			wantLayer1Path: "snapshots/1/fs/etc/os-release",
			wantLayer2Path: "snapshots/2/fs/usr/sbin/nginx",
		},
		{
			name:           "secondary_boot_disk_no_checksums",
			outputSubdir:   "mnt/disks/container_layers",
			wantMetadata:   fmt.Sprintf("%s snapshots/1/fs\n%s snapshots/2/fs\n", chainID1, chainID2),
			wantLayer1Path: "snapshots/1/fs/etc/os-release",
			wantLayer2Path: "snapshots/2/fs/usr/sbin/nginx",
		},
		{
			name:           "boot_disk_in_place",
			outputSubdir:   "var/lib/containerd",
			wantMetadata:   fmt.Sprintf("%s io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs\n%s io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs\n", chainID1, chainID2),
			wantLayer1Path: "io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/etc/os-release",
			wantLayer2Path: "io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs/usr/sbin/nginx",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := setupSnapshotTestEnv(t, tc.initialViews)
			outputDir := filepath.Join(env.rootDir, tc.outputSubdir)

			callCmd := fmt.Sprintf("process_snapshots %q", outputDir)
			if tc.storeChecksums != "" {
				callCmd = fmt.Sprintf("process_snapshots %q %q", outputDir, tc.storeChecksums)
			}
			script := "set -euo pipefail\nsource ./script/startup.sh\nremove_snapshot_views\n" + callCmd + "\n"
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = env.cmdEnv
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("process_snapshots(%q, %q) failed: %v\noutput:\n%s", outputDir, tc.storeChecksums, err, out)
			}

			metadataPath := filepath.Join(outputDir, "snapshots.metadata")
			if gotMetadata, err := os.ReadFile(metadataPath); err != nil {
				t.Errorf("process_snapshots(%q, %q) os.ReadFile(%q) error = %v, want nil", outputDir, tc.storeChecksums, metadataPath, err)
			} else if string(gotMetadata) != tc.wantMetadata {
				t.Errorf("process_snapshots(%q, %q) snapshots.metadata =\n%s\nwant:\n%s", outputDir, tc.storeChecksums, gotMetadata, tc.wantMetadata)
			}

			for _, file := range []struct {
				relPath string
				want    string
			}{
				{relPath: tc.wantLayer1Path, want: osReleaseContents},
				{relPath: tc.wantLayer2Path, want: nginxContents},
			} {
				got, err := os.ReadFile(filepath.Join(outputDir, file.relPath))
				if err != nil || string(got) != file.want {
					t.Errorf("process_snapshots(%q, %q) os.ReadFile(%q) = (%q, %v), want (%q, nil)", outputDir, tc.storeChecksums, file.relPath, got, err, file.want)
				}
			}

			copiedSnapshotsDir := filepath.Join(env.containerdDir, "snapshots")
			if _, err := os.Stat(copiedSnapshotsDir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("process_snapshots(%q, %q) os.Stat(%q) error = %v, want os.ErrNotExist", outputDir, tc.storeChecksums, copiedSnapshotsDir, err)
			}

			if gotViews, err := os.ReadFile(env.viewsFile); err != nil {
				t.Errorf("process_snapshots(%q, %q) os.ReadFile(%q) error = %v, want nil", outputDir, tc.storeChecksums, env.viewsFile, err)
			} else if remaining := strings.TrimSpace(string(gotViews)); remaining != "" {
				t.Errorf("process_snapshots(%q, %q) remaining ctr views = %q, want %q", outputDir, tc.storeChecksums, remaining, "")
			}
		})
	}
}

type snapshotTestEnv struct {
	rootDir       string
	containerdDir string
	viewsFile     string
	cmdEnv        []string
}

func setupSnapshotTestEnv(t *testing.T, initialViews string) *snapshotTestEnv {
	t.Helper()

	rootDir := t.TempDir()
	binDir := filepath.Join(rootDir, "bin")
	containerdDir := filepath.Join(rootDir, "var", "lib", "containerd")
	overlayDir := filepath.Join(containerdDir, "io.containerd.snapshotter.v1.overlayfs")
	secondaryDir := filepath.Join(rootDir, "mnt", "disks", "container_layers")
	snap1File := filepath.Join(overlayDir, "snapshots", "1", "fs", "etc", "os-release")
	snap2File := filepath.Join(overlayDir, "snapshots", "2", "fs", "usr", "sbin", "nginx")
	viewsFile := filepath.Join(rootDir, "views.state")

	for _, dir := range []string{binDir, secondaryDir, filepath.Dir(snap1File), filepath.Dir(snap2File)} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("os.MkdirAll(%q): %v", dir, err)
		}
	}

	if err := os.WriteFile(snap1File, []byte(osReleaseContents), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", snap1File, err)
	}
	if err := os.WriteFile(snap2File, []byte(nginxContents), 0755); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", snap2File, err)
	}
	if err := os.WriteFile(viewsFile, []byte(initialViews), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", viewsFile, err)
	}

	// Fail-fast stubs verify that sourcing startup.sh never triggers setup_environment.
	for _, cmdName := range []string{"apt", "apt-get", "mkfs.ext4", "systemctl", "curl"} {
		stub := fmt.Sprintf("#!/usr/bin/env bash\necho unexpected call to %s >&2\nexit 99\n", cmdName)
		stubPath := filepath.Join(binDir, cmdName)
		if err := os.WriteFile(stubPath, []byte(stub), 0755); err != nil {
			t.Fatalf("os.WriteFile(%q): %v", stubPath, err)
		}
	}
	sudoPath := filepath.Join(binDir, "sudo")
	if err := os.WriteFile(sudoPath, []byte("#!/usr/bin/env bash\nexec \"$@\"\n"), 0755); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", sudoPath, err)
	}
	ctrPath := filepath.Join(binDir, "ctr")
	if err := os.WriteFile(ctrPath, []byte(fakeCtrScript), 0755); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", ctrPath, err)
	}

	cmdEnv := append(
		os.Environ(),
		"PATH="+binDir+":"+os.Getenv("PATH"),
		"CTR_VIEWS_FILE="+viewsFile,
		"CTR_OVERLAY_DIR="+overlayDir,
		"STORE_SNAPSHOT_CHECKSUMS=",
	)

	return &snapshotTestEnv{
		rootDir:       rootDir,
		containerdDir: containerdDir,
		viewsFile:     viewsFile,
		cmdEnv:        cmdEnv,
	}
}

const (
	chainID1          = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	chainID2          = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	osReleaseContents = "ID=cos\nVERSION_ID=121\n"
	nginxContents     = "#!/bin/sh\necho nginx\n"

	// Precomputed directory checksums matching startup.sh's md5sum pipeline:
	// find <fs> -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum.
	osReleaseDirMD5 = "aa8a6d2a13b5b7e3f3f7240b8ad76ef1"
	nginxDirMD5     = "84896427f60f167f68e65de2c912a99f"
)

const fakeCtrScript = `#!/usr/bin/env bash
set -euo pipefail

readonly CHAIN_ID_1="sha256:1111111111111111111111111111111111111111111111111111111111111111"
readonly CHAIN_ID_2="sha256:2222222222222222222222222222222222222222222222222222222222222222"

if [[ "${1:-}" != "-n" || "${2:-}" != "k8s.io" || "${3:-}" != "snapshot" ]]; then
  echo "unexpected ctr args: $*" >&2
  exit 1
fi
shift 3

case "$1" in
  list)
    printf "KEY                                                                     PARENT                                                                  KIND\n"
    printf "%s                                                                        Committed\n" "$CHAIN_ID_1"
    printf "%s  %s  Committed\n" "$CHAIN_ID_2" "$CHAIN_ID_1"
    if [[ -s "$CTR_VIEWS_FILE" ]]; then
      while IFS= read -r view; do
        [[ -z "$view" ]] && continue
        printf "%s  %s  View\n" "$view" "$CHAIN_ID_1"
      done < "$CTR_VIEWS_FILE"
    fi
    ;;
  view)
    if [[ "${2:-}" != "-t" ]]; then
      echo "expected -t flag on ctr snapshot view, got: $*" >&2
      exit 1
    fi
    target="$3"
    view_key="$4"
    snap="$5"
    printf "%s\n" "$view_key" >> "$CTR_VIEWS_FILE"
    case "$snap" in
      "$CHAIN_ID_1")
        printf "mount -t bind %s/snapshots/1/fs %s -o ro,rbind\n" "$CTR_OVERLAY_DIR" "$target"
        ;;
      "$CHAIN_ID_2")
        printf "mount -t overlay overlay %s -o lowerdir=%s/snapshots/2/fs:%s/snapshots/1/fs\n" "$target" "$CTR_OVERLAY_DIR" "$CTR_OVERLAY_DIR"
        ;;
      *)
        echo "unknown snapshot: $snap" >&2
        exit 1
        ;;
    esac
    ;;
  rm)
    view_key="$2"
    if [[ -f "$CTR_VIEWS_FILE" ]]; then
      grep -Fxv "$view_key" "$CTR_VIEWS_FILE" > "${CTR_VIEWS_FILE}.tmp" || true
      mv "${CTR_VIEWS_FILE}.tmp" "$CTR_VIEWS_FILE"
    fi
    ;;
  *)
    echo "unsupported ctr snapshot subcommand: $1" >&2
    exit 1
    ;;
esac
`
