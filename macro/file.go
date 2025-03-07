package macro

import "runtime"

func FILE__() string {
	if _, file, _, ok := runtime.Caller(1); !ok {
		return ""
	} else {
		return file
	}
}
