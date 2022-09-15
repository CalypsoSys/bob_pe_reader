package bob_pe_reader

import (
	"fmt"
	"io/ioutil"
	"strings"
)

type DWORD uint32
type WORD uint16
type BYTE uint8

func readByte(p []byte) BYTE {
	//(((unsigned char*)(p))[0])
	return BYTE(p[0])
}
func readWord(p []byte, offset int) WORD {
	//((((unsigned char*)(p))[0]) | ((((unsigned char*)(p))[1]) << 8))

	return WORD(p[offset+0]) | (WORD(p[offset+1]) << 8)
}

func readDoubleWord(p []byte, offset int) DWORD {
	//((((unsigned char*)(p))[0]) | ((((unsigned char*)(p))[1]) << 8) | ((((unsigned char*)(p))[2]) << 16) | ((((unsigned char*)(p))[3]) << 24))

	return DWORD(p[offset+0]) | (DWORD(p[offset+1]) << 8) | (DWORD(p[offset+2]) << 16) | (DWORD(p[offset+3]) << 24)
}

func pad(x int) DWORD {
	//(((x) + 3) & 0xFFFFFFFC)

	return DWORD(x+3) & 0xFFFFFFFC
}

func printVersion(version []byte, offs int, peInfo map[string]string) int {
	offs = int(pad(offs))

	lenX := readWord(version, offs)
	offs += 2
	valLen := readWord(version, offs)
	offs += 2
	typeX := readWord(version, offs)
	offs += 2

	info := make([]byte, 200)
	for i := 0; i < 200; i++ {
		c := readWord(version, offs)
		offs += 2

		info[i] = byte(c)
		if c == 0 {
			break
		}
	}

	offs = int(pad(offs))

	infoStr := strings.TrimRight(string(info), "\x00")
	if typeX != 0 { //TEXT
		value := make([]byte, 200)
		for i := 0; i < int(valLen); i++ {
			c := readWord(version, offs)
			offs += 2
			value[i] = byte(c)
		}
		peInfo[infoStr] = strings.TrimRight(string(value), "\x00")
	} else {
		if infoStr == "VS_VERSION_INFO" {
			//fixed is a VS_FIXEDFILEINFO
			fixed := version[offs:]
			fileA := readWord(fixed, 10)
			fileB := readWord(fixed, 8)
			fileC := readWord(fixed, 14)
			fileD := readWord(fixed, 12)
			prodA := readWord(fixed, 18)
			prodB := readWord(fixed, 16)
			prodC := readWord(fixed, 22)
			prodD := readWord(fixed, 20)
			peInfo["FileVersion"] = fmt.Sprintf("%d.%d.%d.%d\n", fileA, fileB, fileC, fileD)
			peInfo["ProductVersion"] = fmt.Sprintf("%d.%d.%d.%d\n", prodA, prodB, prodC, prodD)
		}
		offs += int(valLen)
	}

	for offs < int(lenX) {
		offs = printVersion(version, offs, peInfo)
	}
	return int(pad(offs))
}

func FindPeInfo(inputFile string) map[string]string {
	buf, _ := ioutil.ReadFile(inputFile)

	//buf is a IMAGE_DOS_HEADER
	if readWord(buf, 0) != 0x5A4D { //MZ signature
		return nil
	}

	//pe is a IMAGE_NT_HEADERS32
	pe := readDoubleWord(buf, 0x3C)
	if readWord(buf, int(pe)) != 0x4550 { //PE signature
		return nil
	}

	//coff is a IMAGE_FILE_HEADER
	coff := int(pe + 4)

	numSections := readWord(buf, coff+2)
	optHeaderSize := readWord(buf, coff+16)
	if numSections == 0 || optHeaderSize == 0 {
		return nil
	}

	//optHeader is a IMAGE_OPTIONAL_HEADER32
	optHeader := coff + 20
	if readWord(buf, optHeader) != 0x10b { //Optional header magic (32 bits)
		return nil
	}

	//dataDir is an array of IMAGE_DATA_DIRECTORY
	dataDir := optHeader + 96
	vaRes := readDoubleWord(buf, dataDir+8*2)

	//secTable is an array of IMAGE_SECTION_HEADER
	secTable := int(optHeader) + int(optHeaderSize)

	for i := 0; i < int(numSections); i++ {
		//sec is a IMAGE_SECTION_HEADER*
		sec := secTable + 40*i
		secName := strings.TrimRight(string(buf[sec:sec+8]), "\x00")

		if secName != ".rsrc" {
			continue
		}

		vaSec := readDoubleWord(buf, sec+12)
		raw := readDoubleWord(buf, sec+20)

		resSec := int(raw + (vaRes - vaSec))
		numNamed := readWord(buf, resSec+12)
		numId := readWord(buf, resSec+14)

		for j := 0; j < int(numNamed+numId); j++ {
			//resSec is a IMAGE_RESOURCE_DIRECTORY followed by an array
			// of IMAGE_RESOURCE_DIRECTORY_ENTRY
			res := resSec + 16 + 8*j
			name := readDoubleWord(buf, res)
			if name != 16 { //RT_VERSION
				continue
			}

			offs := int(readDoubleWord(buf, res+4))
			if (offs & 0x80000000) == 0 { //is a dir resource?
				return nil
			}
			//verDir is another IMAGE_RESOURCE_DIRECTORY and
			// IMAGE_RESOURCE_DIRECTORY_ENTRY array
			verDir := resSec + (offs & 0x7FFFFFFF)

			numNamed := readWord(buf, verDir+12)
			numId := readWord(buf, verDir+14)
			if numNamed == 0 && numId == 0 {
				return nil
			}
			res = int(verDir + 16)
			offs = int(readDoubleWord(buf, res+4))
			if (offs & 0x80000000) == 0 { //is a dir resource?
				return nil
			}

			//and yet another IMAGE_RESOURCE_DIRECTORY, etc.
			verDir = resSec + (offs & 0x7FFFFFFF)
			numNamed = readWord(buf, verDir+12)
			numId = readWord(buf, verDir+14)
			if numNamed == 0 && numId == 0 {
				return nil
			}
			res = verDir + 16
			offs = int(readDoubleWord(buf, res+4))
			if (offs & 0x80000000) != 0 { //is a dir resource?
				return nil
			}
			verDir = resSec + offs

			verVa := readDoubleWord(buf, verDir)

			verPtr := raw + (verVa - vaSec)

			rc := map[string]string{}
			printVersion(buf[verPtr:], 0, rc)
			return rc
		}
	}

	return nil
}
