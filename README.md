# bob_pe_reader
bob_pe_reader - a golang library to read windowes PE info from exe and dll

Originally taken from the answer by @rodrigo, found here: http://stackoverflow.com/a/12486703/850326

see https://en.wikipedia.org/wiki/Portable_Executable
    https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
    https://wiki.osdev.org/PE

Sample code

```
package main

import (
	"fmt"
	"github.com/CalypsoSys/bob_pe_reader"
)

func main() {

	fmt.Printf("Testing Bob PE Reader\n")

	infoMap := bob_pe_reader.FindPeInfo(`C:\code\bin\MyWindowsAssembly.dll`)
	for k, v := range infoMap {
		fmt.Printf("%s: %s\n", k, v)
	}
}

```