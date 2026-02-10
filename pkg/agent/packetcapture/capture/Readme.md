# Exploring Antrea PacketCapture BPF Generation Against tcpdump

I would like to explain the output of the two functions that I wrote one with tcpdump -d and the other one with tcpdump -ddd
The functions that I wrote are -
```
func TestTcpdumpAndAntreaBPFOutput
func TestTcpdumpAndAntreaBPFOutputWithddd

```
The output of the first function is -
```
bpf_tcpdump_test.go:28: 
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

```
## Classic BPF Virtual Machine (Background)

Classic BPF (cBPF) programs are executed by a simple virtual machine in the Linux
kernel to decide whether a packet should be accepted or rejected.

The cBPF VM is deliberately minimal and consists of:

- An accumulator register (`A`)
- An index register (`X`)
- A small scratch memory (`M[0..15]`)
- A linear instruction stream with conditional jumps

Each instruction operates on packet data or VM registers and advances the
program counter either sequentially or via jump offsets.
A non-zero value means accept the packet and 0 means reject it.

- A word is 32 bit and a half word is 16 bit ldh means load half word in register A at offset 12 which the location of the ethertype field of the ethernet header 0x0800 means IPV4 and 0x86dd means IPV6.A single bpf instruction consist of an array of 4 tuples that  contains code, jt, jf and k value - code is the actual filter condition jt is jump if true , jf is jump if false,k is a generic value .

## Test 1: Comparing tcpdump -d and Antrea Assembly Output

### tcpdump -d Output (Human-readable)
```
(001) jeq #0x86dd jt 2 jf 7
 ```
 jeq means jump if equal
Compare EtherType of the current packet  with 0x86dd (IPv6)
If true, jump to instruction (002)
If false, jump to instruction (007)

```
(002) ldb [20]
```
ldb means load byte
[20] is offset 20 bytes into the packet
For IPv6, this offset corresponds to the Next Header field
This loads the L4 protocol value which can be TCP,UDP etc.

```
(003) jeq #0x6 jt 10 jf 4
 ```
This checks whether the protocol is 6 (TCP)
If true,jump to accept path
If false, continue checking other possibilities 

```
(004) jeq #0x2c jt 5 jf 11
```
0x2c is the IPv6 Fragment Header. This handles fragmented IPv6 packets

```
(005) ldb [54]
(006) jeq #0x6 jt 10 jf 11
```
The first instruction loads the protocol field from the fragment-adjusted offset.
It checks for TCP after fragment handling, if not TCP, the packet is rejected.
Upto the above instruction it is handling of the IPV6 packet. For now on it is about IPV4.

```
(007) jeq #0x800 jt 8 jf 11
(008) ldb [23]
(009) jeq #0x6 jt 10 jf 11
(010) ret #262144
(011) ret #0
```
It check for EtherType 0x0800 (IPv4),If IPv4, jump to IPv4 handling path,Otherwise, reject the packet.
For IPv4, offset 23 corresponds to the Protocol field,loads the L4 protocol number.
It checks whether the IPv4 protocol is TCP, packets which are not Tcp are rejected.
The last two instructions are return statements 0 means reject the packet and 262144 means accept it it matches the filter.


### Antrea Assembled BPF Output

LoadAbsolute - it means load the exact offset from the packet to register A .

```
(000) bpf.LoadAbsolute ldh [12]
 ```
 is equivalent to ``` ldh [12] ``` in tcpdump.
 Now in antrea part of the function the ip addresses are explicitly mentioned in the function so IPV6 checking logic is not there.
Antrea injects additional address checks derived from the PacketCapture
specification:

```
bpf.LoadAbsolute ld [26]
bpf.JumpIf jneq #2130706433,3   // src IP 127.0.0.1

bpf.LoadAbsolute ld [30]
bpf.JumpIf jneq #2130706434,1   // dst IP 127.0.0.2
```
These checks narrow the filter to traffic between specific endpoints, which is
required by the PacketCapture CRD.
2048 = 0x0800 (IPv4) 
Both filters end with:
```
ret #262144   // accept packet
ret #0        // reject packet
``` 
This confirms semantic equivalence.

### Test 2: Comparing Kernel Bytecode with tcpdump -ddd

Here  I have used -ddd which is to the lowest level and it compare the bytecode for the kernel . It is the lowest level of comparision, it compares what the kernel finally sees.
It is loaded into the linux kernel as `struct sock_filter`
instructions.
The output of the function is -

```
 bpf_tcpdump_test.go:75: === tcpdump BPF ===
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

```
12 represents the total number of bpf instructions.
Each subsequent line represents one struct sock_filter instruction in the
format:
```
<opcode> <jt> <jf> <k>
```
-opcode is the classic BPF operation (load, jump, return, etc.)
-jt is the jump offset if the condition is true
-jf is the jump offset if the condition is false.
- k is the immediate constant or packet offset

There is one helper function
```
func assembleAntrea(insts []bpf.Instruction)
```

Antrea generates BPF programs as structured Go instructions
(`[]bpf.Instruction`). These are assembled into kernel bytecode using:
bpf.Assemble(insts) which produces []bpf.RawInstruction.

## Summary and Intent

This exploratory work on my part that demonstrates that Antrea’s PacketCapture BPF generation
can be systematically compared against tcpdump at both the assembly and
kernel bytecode levels. 

## Resources I have used to this work-

[Linux classic BPF documentation (filter.rst)](https://www.kernel.org/doc/Documentation/networking/filter.rst)
