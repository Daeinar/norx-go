# NORX source code package (Go)

## Warning
[NORX](https://norx.io) is still a rather new authenticated encryption algorithm. The authors are confident that it is secure but nevertheless NORX **still lacks extensive analysis**. Therefore, **do not use** it in your applications!

## About
This repository provides a Go implementation of NORX6441 v2.0. The NORX AEAD algorithm family was designed by

  * [Jean-Philippe Aumasson](https://aumasson.jp)
  * [Philipp Jovanovic](https://zerobyte.io)
  * [Samuel Neves](http://eden.dei.uc.pt/~sneves/)

## Installation & Usage
To check out the source code execute:
```
go get github.com/daeinar/norx-go
```

To install NORX and run the test vectors execute:
```
go install && norx-go check
```

## License
The NORX source code is released under the [CC0 license](https://creativecommons.org/publicdomain/zero/1.0/). The full license text is included in the file `LICENSE`.
