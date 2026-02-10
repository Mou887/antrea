package capture

import (
	"net"
	"os/exec"
	"testing"
	"golang.org/x/net/bpf"


	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)
// Here I am trying to compare the tcpdump -d "tcp" to antrea's compilePacketFilter to see the similarity and the
//  differences between the two generated outputs

func TestTcpdumpAndAntreaBPFOutput(t *testing.T) {
	// --- Part 1: tcpdump output ---
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump not installed")
	}

	tcpdumpCmd := exec.Command("tcpdump", "-d", "tcp")
	tcpdumpOut, err := tcpdumpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tcpdump failed: %v", err)
	}

	t.Log("=== tcpdump BPF ===")
	t.Log("\n" + string(tcpdumpOut))

	// --- Part 2: Antrea output ---
	packet := &crdv1alpha1.Packet{
		Protocol: &testTCPProtocol,
	}

	antreaInst := compilePacketFilter(
		packet,
		net.ParseIP("127.0.0.1"),
		net.ParseIP("127.0.0.2"),
		crdv1alpha1.CaptureDirectionSourceToDestination,
	)

	if len(antreaInst) == 0 {
		t.Fatalf("Antrea generated no BPF instructions")
	}

	t.Log("=== Antrea BPF (assembled) ===")
	for i, ins := range antreaInst {
		// %T prints the instruction type (LoadAbsolute, JumpIf, etc.)
		t.Logf("(%03d) %T %+v", i, ins, ins)
	}
}

// The output of the above function is -
//=== RUN   TestTcpdumpAndAntreaBPFOutput
//    bpf_tcpdump_test.go:27: === tcpdump BPF ===
//    bpf_tcpdump_test.go:28: 
//        Warning: assuming Ethernet
//        (000) ldh      [12]
//        (001) jeq      #0x86dd          jt 2    jf 7
//        (002) ldb      [20]
//        (003) jeq      #0x6             jt 10   jf 4
//        (004) jeq      #0x2c            jt 5    jf 11
//        (005) ldb      [54]
//       (006) jeq      #0x6             jt 10   jf 11
//       (007) jeq      #0x800           jt 8    jf 11
//       (008) ldb      [23]
//        (009) jeq      #0x6             jt 10   jf 11
//        (010) ret      #262144
//        (011) ret      #0
        
//    bpf_tcpdump_test.go:46: === Antrea BPF (assembled) ===
//    bpf_tcpdump_test.go:49: (000) bpf.LoadAbsolute ldh [12]
//    bpf_tcpdump_test.go:49: (001) bpf.JumpIf jneq #2048,7
//    bpf_tcpdump_test.go:49: (002) bpf.LoadAbsolute ldb [23]
//    bpf_tcpdump_test.go:49: (003) bpf.JumpIf jneq #6,5
 //   bpf_tcpdump_test.go:49: (004) bpf.LoadAbsolute ld [26]
 //   bpf_tcpdump_test.go:49: (005) bpf.JumpIf jneq #2130706433,3
 //   bpf_tcpdump_test.go:49: (006) bpf.LoadAbsolute ld [30]
 //   bpf_tcpdump_test.go:49: (007) bpf.JumpIf jneq #2130706434,1
 //   bpf_tcpdump_test.go:49: (008) bpf.RetConstant ret #262144
 //   bpf_tcpdump_test.go:49: (009) bpf.RetConstant ret #0
//--- PASS: TestTcpdumpAndAntreaBPFOutput (0.02s)

// Switching to tcpdump -ddd option

func assembleAntrea(insts []bpf.Instruction) []bpf.RawInstruction {
	raw, err := bpf.Assemble(insts)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestTcpdumpAndAntreaBPFOutputWithddd(t *testing.T) {
	// --- Part 1: tcpdump output ---
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump not installed")
	}

	tcpdumpCmd := exec.Command("tcpdump", "-ddd", "tcp")
	tcpdumpOut, err := tcpdumpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tcpdump failed: %v", err)
	}

	t.Log("=== tcpdump BPF ===")
	t.Log("\n" + string(tcpdumpOut))

	// --- Part 2: Antrea output ---
	packet := &crdv1alpha1.Packet{
		Protocol: &testTCPProtocol,
	}

	antreaInst := compilePacketFilter(
		packet,
		net.ParseIP("127.0.0.1"),
		net.ParseIP("127.0.0.2"),
		crdv1alpha1.CaptureDirectionSourceToDestination,
	)

	if len(antreaInst) == 0 {
		t.Fatalf("Antrea generated no BPF instructions")
	}


	t.Log("=== Antrea raw BPF ===")
  for i, r := range assembleAntrea(antreaInst) {
	t.Logf("%02d: Op=%d Jt=%d Jf=%d K=%d", i, r.Op, r.Jt, r.Jf, r.K)
}
}
// The output of the second function
//go test ./pkg/agent/packetcapture/capture \
//  -run TestTcpdumpAndAntreaBPFOutputWithddd \
//  -v
//=== RUN   TestTcpdumpAndAntreaBPFOutputWithddd
//    bpf_tcpdump_test.go:75: === tcpdump BPF ===
//    bpf_tcpdump_test.go:76: 
//        Warning: assuming Ethernet
//        12
//        40 0 0 12
//        21 0 5 34525
//       48 0 0 20
//        21 6 0 6
//       21 0 6 44
//       48 0 0 54
//       21 3 4 6
//        21 0 3 2048
//       48 0 0 23
//        21 0 1 6
//       6 0 0 262144
//       6 0 0 0
        
//    bpf_tcpdump_test.go:95: === Antrea raw BPF ===
//    bpf_tcpdump_test.go:97: 00: Op=40 Jt=0 Jf=0 K=12
 //   bpf_tcpdump_test.go:97: 01: Op=21 Jt=0 Jf=7 K=2048
 //   bpf_tcpdump_test.go:97: 02: Op=48 Jt=0 Jf=0 K=23
 //   bpf_tcpdump_test.go:97: 03: Op=21 Jt=0 Jf=5 K=6
 //   bpf_tcpdump_test.go:97: 04: Op=32 Jt=0 Jf=0 K=26
 //   bpf_tcpdump_test.go:97: 05: Op=21 Jt=0 Jf=3 K=2130706433
 //   bpf_tcpdump_test.go:97: 06: Op=32 Jt=0 Jf=0 K=30
 //   bpf_tcpdump_test.go:97: 07: Op=21 Jt=0 Jf=1 K=2130706434
//    bpf_tcpdump_test.go:97: 08: Op=6 Jt=0 Jf=0 K=262144
 //   bpf_tcpdump_test.go:97: 09: Op=6 Jt=0 Jf=0 K=0
//--- PASS: TestTcpdumpAndAntreaBPFOutputWithddd (0.02s)
//PASS
//ok      antrea.io/antrea/pkg/agent/packetcapture/capture        (cached)