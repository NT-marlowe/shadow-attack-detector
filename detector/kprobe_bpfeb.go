// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadKprobe returns the embedded CollectionSpec for kprobe.
func loadKprobe() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KprobeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load kprobe: %w", err)
	}

	return spec, err
}

// loadKprobeObjects loads kprobe and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*kprobeObjects
//	*kprobePrograms
//	*kprobeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadKprobeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadKprobe()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// kprobeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type kprobeSpecs struct {
	kprobeProgramSpecs
	kprobeMapSpecs
}

// kprobeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type kprobeProgramSpecs struct {
	KprobeExecve *ebpf.ProgramSpec `ebpf:"kprobe_execve"`
}

// kprobeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type kprobeMapSpecs struct {
	KprobeMap *ebpf.MapSpec `ebpf:"kprobe_map"`
}

// kprobeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadKprobeObjects or ebpf.CollectionSpec.LoadAndAssign.
type kprobeObjects struct {
	kprobePrograms
	kprobeMaps
}

func (o *kprobeObjects) Close() error {
	return _KprobeClose(
		&o.kprobePrograms,
		&o.kprobeMaps,
	)
}

// kprobeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadKprobeObjects or ebpf.CollectionSpec.LoadAndAssign.
type kprobeMaps struct {
	KprobeMap *ebpf.Map `ebpf:"kprobe_map"`
}

func (m *kprobeMaps) Close() error {
	return _KprobeClose(
		m.KprobeMap,
	)
}

// kprobePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadKprobeObjects or ebpf.CollectionSpec.LoadAndAssign.
type kprobePrograms struct {
	KprobeExecve *ebpf.Program `ebpf:"kprobe_execve"`
}

func (p *kprobePrograms) Close() error {
	return _KprobeClose(
		p.KprobeExecve,
	)
}

func _KprobeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kprobe_bpfeb.o
var _KprobeBytes []byte
