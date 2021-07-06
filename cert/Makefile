.PHONY: gen-proto
gen-proto:
	(cd src ; mkdir temp ; protoc --rust_out temp cert.proto ; mv temp/cert.rs cert_pb.rs ; rmdir temp)