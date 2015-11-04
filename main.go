/*
    main.go
    ------

    This file is part of the Go reference implementation of NORX.

    :version: v2.0
    :copyright: (c) 2014, 2015 Philipp Jovanovic <philipp@jovanovic.io>
    :license: CC0, see LICENSE
*/

package main

import "fmt"
import "os"
import utils "github.com/daeinar/norx-go/utils"

func main() {

    args := os.Args

    if len(args) != 2 {
        fmt.Println("Error: Too few parameter.")
    } else {
        if args[1] == "check" {
            utils.Check()
        } else if args[1] == "genkat" {
            utils.Genkat()
        } else if args[1] == "debug" {
            utils.Debug()
        } else {
            fmt.Println("Error: Unknown parameter.")
        }
    }


}
