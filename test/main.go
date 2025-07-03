package main

/*
#cgo LDFLAGS: -L./lib -lcustody_rsa
#include <stdlib.h>
#include "./lib/custody_rsa.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func private_encrypt(priv, data string) (ret string, err error) {
	defer func() {
		if re := recover(); re != nil {
			err = fmt.Errorf("%+v", re)
		}
	}()

	privPtr := C.CString(priv)
	defer C.free(unsafe.Pointer(privPtr))

	dataPtr := C.CString(data)
	defer C.free(unsafe.Pointer(dataPtr))

	enData := C.private_key_encrypt(privPtr, dataPtr)
	ret = C.GoString(enData)
	C.free(unsafe.Pointer(enData))
	return
}
