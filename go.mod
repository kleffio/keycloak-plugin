module github.com/kleffio/idp-keycloak

go 1.25.0

require (
	github.com/kleffio/plugin-sdk-go v0.1.3-0.20260413213743-84d4baf9639c
	google.golang.org/grpc v1.64.0
)

replace github.com/kleffio/plugin-sdk-go => ../plugin-sdk-go

require (
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240617180043-68d350f18fd4 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
