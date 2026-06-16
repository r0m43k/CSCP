package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) == 1 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "scan":
		runScanCommand(os.Args[2:])
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("usage: cscp scan")
}
