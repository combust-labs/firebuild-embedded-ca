# firebuild embedded CA

An in-memory certificate authority used by firebuild during a `rootfs` build process.

## Usage

```golang
package main

import (
    "github.com/combust-labs/firebuild-embedded-ca/ca"
    "github.com/hashicorp/go-hclog"
	"google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {

    logger := hclog.Default()

    grpcServiceName := "grpc-service-name"

    grpcServerOptions := []grpc.ServerOption{}

    embeddedCA, embeddedCAErr := ca.NewDefaultEmbeddedCAWithLogger(&ca.EmbeddedCAConfig{
        Addresses: []string{grpcServiceName},
        KeySize:   4096,
    }, logger.Named("embdedded-ca"))
    if embeddedCAErr != nil {
        panic(embeddedCAErr)
    }

    serverTLSConfig, tlsConfigErr := embeddedCA.NewServerCertTLSConfig()
    if tlsConfigErr != nil {
        panic(tlsConfigErr)
    }

    clientTLSConfig, err := embeddedCA.NewClientCertTLSConfig(grpcServiceName)
    if err != nil {
        panic(embeddedCAErr)
    }

    grpcServerOptions = append(grpcServerOptions, grpc.Creds(credentials.NewTLS(serverTLSConfig)))

    listener, listenerErr := net.Listen("tcp", "127.0.0.1:0")
    if listenerErr != nil {
        panic(listenerErr)
    }

    grpcServer = grpc.NewServer(grpcServerOptions...)
    ///proto.Register...(grpcServer, ...)

    chanErr := make(chan struct{})
    go func() {
        if err := s.srv.Serve(listener); err != nil {
            logger.Error("failed grpc serve", "reason", err)
            close(chanErr)
        }
    }()

    grpcConn, _ := grpc.Dial(listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLSConfig)))
    
    // ...

}
```