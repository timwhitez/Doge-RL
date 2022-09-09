package main

import (
	"bytes"
	"fmt"
	"github.com/Binject/debug/pe"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func main() {
	fileName := os.Args[1]
	function0 := os.Args[2]
	buf, e := os.ReadFile(fileName)
	if e != nil {
		panic(e)
	}

	Ldr1(fileName, function0)
	Ldr2(buf, function0)
}

func Ldr1(fn, funcn string) {
	p, e := pe.Open(fn)
	if e != nil {
		panic(e)
	}

	//funcN := "ReflectiveLoader"
	funcN := funcn

	ex, e := p.Exports()
	if e != nil {
		panic(e)
	}
	var RDIOffset uintptr
	for _, exp := range ex {
		if strings.Contains(strings.ToLower(exp.Name), strings.ToLower(funcN)) {
			RDIOffset = uintptr(rvaToOffset(p, exp.VirtualAddress))
		}
	}
	fmt.Printf("Offset: 0x%x\n", RDIOffset)

	buf, e := p.Bytes()
	if e != nil {
		panic(e)
	}

	va := syscall.NewLazyDLL("kernel32").NewProc("VirtualAlloc").Addr()
	ba, _, _ := syscall.SyscallN(va, 0, uintptr(len(buf)), 0x1000|0x2000, syscall.PAGE_EXECUTE_READWRITE)
	if ba == 0 {
		panic("VirtualAlloc")
	}
	writeMem(ba, buf)

	Ldr := ba + RDIOffset

	syscall.SyscallN(Ldr)
}

func Ldr2(buf []byte, funcn string) {

	p, e := pe.NewFile(bytes.NewReader(buf))
	if e != nil {
		panic(e)
	}

	//funcN := "ReflectiveLoader"
	funcN := funcn

	ex, e := p.Exports()
	if e != nil {
		panic(e)
	}
	var RDIOffset uintptr
	for _, exp := range ex {
		if strings.Contains(strings.ToLower(exp.Name), strings.ToLower(funcN)) {
			RDIOffset = uintptr(rvaToOffset(p, exp.VirtualAddress))
		}
	}
	fmt.Printf("Offset: 0x%x\n", RDIOffset)

	va := syscall.NewLazyDLL("kernel32").NewProc("VirtualAlloc").Addr()
	ba, _, _ := syscall.SyscallN(va, 0, uintptr(len(buf)), 0x1000|0x2000, syscall.PAGE_EXECUTE_READWRITE)
	if ba == 0 {
		panic("VirtualAlloc")
	}
	writeMem(ba, buf)

	Ldr := ba + RDIOffset

	syscall.Syscall(Ldr, 0, 0, 0, 0)

}

// rvaToOffset converts an RVA value from a PE file into the file offset. When using binject/debug, this should work fine even with in-memory files.
func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

func writeMem(destination uintptr, inbuf []byte) {
	for index := uint32(0); index < uint32(len(inbuf)); index++ {
		writePtr := unsafe.Pointer(destination + uintptr(index))
		v := (*byte)(writePtr)
		*v = inbuf[index]
	}
}
