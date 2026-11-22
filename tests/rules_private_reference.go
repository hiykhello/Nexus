// Differential reference for the fixed sing-box dependency's IsPublicAddr.
package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
)

func main() {
	input := bufio.NewScanner(os.Stdin)
	output := bufio.NewWriter(os.Stdout)
	defer output.Flush()
	for input.Scan() {
		addr, err := netip.ParseAddr(input.Text())
		if err != nil {
			os.Exit(1)
		}
		private := addr.IsPrivate() || addr.IsLoopback() || addr.IsMulticast() ||
			addr.IsLinkLocalUnicast() || addr.IsInterfaceLocalMulticast() || addr.IsUnspecified()
		if private {
			fmt.Fprintln(output, "1")
		} else {
			fmt.Fprintln(output, "0")
		}
	}
	if input.Err() != nil {
		os.Exit(1)
	}
}
