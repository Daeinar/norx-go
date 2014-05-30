### Go Reference Implementation of NORX

Go implementation of [NORX](https://norx.io), a parallel and scalable authenticated encryption algorithm.

Currently only NORX64 in sequential mode is supported.

NORX was designed by [Jean-Philippe Aumasson](https://aumasson.jp), [Philipp Jovanovic](http://cryptomaths.com) and [Samuel Neves](http://eden.dei.uc.pt/~sneves/).


####Installation
```
go get https://github.com/Daeinar/norx-go
```

####Usage
The following command installs norx-go and runs the test vectors from `test.go`:
```
go install && norx-go
```

####License
This software package is released under the BSD (3-Clause) license. See the file `LICENSE` for more details.
