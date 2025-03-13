package macro

import "runtime"

func LINE__() int {
	if _, _, line, ok := runtime.Caller(1); !ok {
		return -1
	} else {
		return line
	}
}
