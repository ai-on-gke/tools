package imager

import (
	"os"
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
