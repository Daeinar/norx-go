/*
    main.go
    ------

    This file is part of the Go reference implementation of NORX.

    :copyright: (c) 2014, 2015 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package main

import "os"
import "fmt"
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
        } else {
            fmt.Println("Error: Unknown parameter.")
        }
    }

}
