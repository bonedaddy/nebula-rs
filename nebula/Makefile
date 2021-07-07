.PHONY: gen-proto
gen-proto:
	(cd src ; mkdir temp ; protoc --rust_out temp nebula.proto ; mv temp/nebula.rs nebula_pb.rs ; rmdir temp)