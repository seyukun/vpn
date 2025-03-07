module wgvpm

go 1.23.5

require github.com/pkg/taptun v0.0.0-20160424131934-bbbd335672ab

require golang.org/x/sys v0.31.0 // indirect

replace github.com/pkg/taptun => ./vendor_extends/github.com/pkg/taptun
