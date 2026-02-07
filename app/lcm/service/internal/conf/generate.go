package conf

//go:generate protoc --experimental_allow_proto3_optional -I=.  --go_out=paths=source_relative:. ./conf.proto
