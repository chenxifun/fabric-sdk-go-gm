module github.com/BSNDA/fabric-sdk-go-gm

go 1.14

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/cloudflare/cfssl v0.0.0-20180202232422-27b05afbb513
	github.com/go-kit/kit v0.10.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang/mock v1.5.0
	github.com/golang/protobuf v1.4.3
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/hyperledger/fabric v1.4.3
	github.com/hyperledger/fabric-lib-go v1.0.0
	github.com/hyperledger/fabric-protos-go v0.0.0-20200124220212-e9cfc186ba7b
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.4.1
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.10.0
	github.com/spf13/cast v1.3.1
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/sykesm/zap-logfmt v0.0.4 // indirect
	github.com/tjfoc/gmsm v1.4.0
	github.com/tjfoc/gmtls v1.2.1
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b
	golang.org/x/net v0.0.0-20210423184538-5f58ad60dda6
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98 // indirect
	google.golang.org/grpc v1.31.0
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/yaml.v2 v2.4.0
)

replace (
	github.com/tjfoc/gmsm => github.com/chenxifun/gmsm v1.4.0
	github.com/tjfoc/gmtls => github.com/chenxifun/gmtls v1.2.1-0.20210427064604-124283070ca7
	)

