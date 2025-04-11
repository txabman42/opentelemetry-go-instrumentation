// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

package sql

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfSliceArrayBuff struct{ Buff [1024]uint8 }

type bpfSpanContext struct {
	TraceID    [16]uint8
	SpanID     [8]uint8
	TraceFlags uint8
	Padding    [7]uint8
}

type bpfSqlRequestT struct {
	StartTime uint64
	EndTime   uint64
	Sc        bpfSpanContext
	Psc       bpfSpanContext
	Query     [256]int8
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
	bpfVariableSpecs
}

// bpfProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	UprobeExecDC          *ebpf.ProgramSpec `ebpf:"uprobe_execDC"`
	UprobeExecDC_Returns  *ebpf.ProgramSpec `ebpf:"uprobe_execDC_Returns"`
	UprobeQueryDC         *ebpf.ProgramSpec `ebpf:"uprobe_queryDC"`
	UprobeQueryDC_Returns *ebpf.ProgramSpec `ebpf:"uprobe_queryDC_Returns"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	AllocMap                  *ebpf.MapSpec `ebpf:"alloc_map"`
	Events                    *ebpf.MapSpec `ebpf:"events"`
	GoContextToSc             *ebpf.MapSpec `ebpf:"go_context_to_sc"`
	GolangMapbucketStorageMap *ebpf.MapSpec `ebpf:"golang_mapbucket_storage_map"`
	ProbeActiveSamplerMap     *ebpf.MapSpec `ebpf:"probe_active_sampler_map"`
	SamplersConfigMap         *ebpf.MapSpec `ebpf:"samplers_config_map"`
	SliceArrayBuffMap         *ebpf.MapSpec `ebpf:"slice_array_buff_map"`
	SqlEvents                 *ebpf.MapSpec `ebpf:"sql_events"`
	TrackedSpansBySc          *ebpf.MapSpec `ebpf:"tracked_spans_by_sc"`
}

// bpfVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfVariableSpecs struct {
	EndAddr                  *ebpf.VariableSpec `ebpf:"end_addr"`
	Hex                      *ebpf.VariableSpec `ebpf:"hex"`
	ShouldIncludeDbStatement *ebpf.VariableSpec `ebpf:"should_include_db_statement"`
	StartAddr                *ebpf.VariableSpec `ebpf:"start_addr"`
	TotalCpus                *ebpf.VariableSpec `ebpf:"total_cpus"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
	bpfVariables
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	AllocMap                  *ebpf.Map `ebpf:"alloc_map"`
	Events                    *ebpf.Map `ebpf:"events"`
	GoContextToSc             *ebpf.Map `ebpf:"go_context_to_sc"`
	GolangMapbucketStorageMap *ebpf.Map `ebpf:"golang_mapbucket_storage_map"`
	ProbeActiveSamplerMap     *ebpf.Map `ebpf:"probe_active_sampler_map"`
	SamplersConfigMap         *ebpf.Map `ebpf:"samplers_config_map"`
	SliceArrayBuffMap         *ebpf.Map `ebpf:"slice_array_buff_map"`
	SqlEvents                 *ebpf.Map `ebpf:"sql_events"`
	TrackedSpansBySc          *ebpf.Map `ebpf:"tracked_spans_by_sc"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.AllocMap,
		m.Events,
		m.GoContextToSc,
		m.GolangMapbucketStorageMap,
		m.ProbeActiveSamplerMap,
		m.SamplersConfigMap,
		m.SliceArrayBuffMap,
		m.SqlEvents,
		m.TrackedSpansBySc,
	)
}

// bpfVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfVariables struct {
	EndAddr                  *ebpf.Variable `ebpf:"end_addr"`
	Hex                      *ebpf.Variable `ebpf:"hex"`
	ShouldIncludeDbStatement *ebpf.Variable `ebpf:"should_include_db_statement"`
	StartAddr                *ebpf.Variable `ebpf:"start_addr"`
	TotalCpus                *ebpf.Variable `ebpf:"total_cpus"`
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	UprobeExecDC          *ebpf.Program `ebpf:"uprobe_execDC"`
	UprobeExecDC_Returns  *ebpf.Program `ebpf:"uprobe_execDC_Returns"`
	UprobeQueryDC         *ebpf.Program `ebpf:"uprobe_queryDC"`
	UprobeQueryDC_Returns *ebpf.Program `ebpf:"uprobe_queryDC_Returns"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.UprobeExecDC,
		p.UprobeExecDC_Returns,
		p.UprobeQueryDC,
		p.UprobeQueryDC_Returns,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_arm64_bpfel.o
var _BpfBytes []byte
