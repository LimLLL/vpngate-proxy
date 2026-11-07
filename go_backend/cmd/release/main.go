package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// releaseSource is an allowlist so ui_auth.json, logs and cached state never
// enter the distribution archive, regardless of files in the source directory.
var releaseSource = []string{
	".dockerignore", "VERSION", "README.md", "RELEASE_NOTES.md", "LICENSE",
	"install.sh", "Dockerfile", "compose.yaml", "mirror", "go_backend",
}

func main() {
	root := flag.String("root", ".", "repository root")
	output := flag.String("output-dir", "dist", "archive output directory")
	artifacts := flag.String("artifacts", filepath.Join("dist", "native"), "compiled native application and bridge")
	flag.Parse()
	if err := build(*root, *output, *artifacts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build(root, output, artifacts string) error {
	versionData, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return err
	}
	version := strings.TrimSpace(string(versionData))
	if !regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,2}$`).MatchString(version) {
		return errors.New("VERSION must contain two or three numeric components")
	}
	name := "aimilivpn-v" + version + "-linux-native"
	if err := os.MkdirAll(output, 0o755); err != nil {
		return err
	}
	archiveName := filepath.Join(output, name+".tar.gz")
	archive, err := os.OpenFile(archiveName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("archive must not overwrite existing output: %w", err)
	}
	gzipWriter := gzip.NewWriter(archive)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, relative := range releaseSource {
		if err := appendTree(tarWriter, filepath.Join(root, relative), filepath.Join(name, relative)); err != nil {
			closeArchive(tarWriter, gzipWriter, archive)
			return err
		}
	}
	for _, source := range []string{"vpngate-proxy", "libvpngate_bridge.so"} {
		directory := "lib"
		if source == "vpngate-proxy" {
			directory = "bin"
		}
		path := filepath.Join(artifacts, source)
		target := filepath.Join(name, directory, source)
		if err := appendFile(tarWriter, path, target, 0o755); err != nil {
			closeArchive(tarWriter, gzipWriter, archive)
			return fmt.Errorf("required native binary: %w", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = archive.Close()
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		_ = archive.Close()
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	file, err := os.Open(archiveName)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, hashErr := io.Copy(digest, file)
	readErr := file.Close()
	if hashErr != nil {
		return hashErr
	}
	if readErr != nil {
		return readErr
	}
	checksum := hex.EncodeToString(digest.Sum(nil)) + "  " + filepath.Base(archiveName) + "\n"
	if err := os.WriteFile(filepath.Join(output, "sha256sums.txt"), []byte(checksum), 0o644); err != nil {
		return err
	}
	fmt.Println(archiveName)
	return nil
}

func appendTree(writer *tar.Writer, root, name string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		target := filepath.ToSlash(filepath.Join(name, relative))
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is not an allowed release input: %s", path)
		}
		if info.IsDir() {
			return writer.WriteHeader(&tar.Header{Name: target + "/", Mode: 0o755, Typeflag: tar.TypeDir})
		}
		return appendFile(writer, path, target, info.Mode().Perm())
	})
}

func appendFile(writer *tar.Writer, source, target string, mode os.FileMode) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("not a regular release file: %s", source)
	}
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	header := &tar.Header{Name: filepath.ToSlash(target), Size: info.Size(), Mode: int64(mode.Perm()), Typeflag: tar.TypeReg}
	if err := writer.WriteHeader(header); err != nil {
		_ = file.Close()
		return err
	}
	_, err = io.Copy(writer, file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func closeArchive(t *tar.Writer, g *gzip.Writer, f *os.File) {
	_ = t.Close()
	_ = g.Close()
	_ = f.Close()
}
