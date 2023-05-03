// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.12.4
// source: pkg/gophkeeper.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	GophKeeper_Register_FullMethodName    = "/proto.GophKeeper/Register"
	GophKeeper_Login_FullMethodName       = "/proto.GophKeeper/Login"
	GophKeeper_UpdatePass_FullMethodName  = "/proto.GophKeeper/UpdatePass"
	GophKeeper_GetMetadata_FullMethodName = "/proto.GophKeeper/GetMetadata"
	GophKeeper_AddEntry_FullMethodName    = "/proto.GophKeeper/AddEntry"
	GophKeeper_GetEntry_FullMethodName    = "/proto.GophKeeper/GetEntry"
	GophKeeper_UpdateEntry_FullMethodName = "/proto.GophKeeper/UpdateEntry"
	GophKeeper_DeleteEntry_FullMethodName = "/proto.GophKeeper/DeleteEntry"
)

// GophKeeperClient is the client API for GophKeeper service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type GophKeeperClient interface {
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error)
	UpdatePass(ctx context.Context, in *UpdatePassRequest, opts ...grpc.CallOption) (*UpdatePassResponse, error)
	GetMetadata(ctx context.Context, in *GetMetadataRequest, opts ...grpc.CallOption) (*GetMetadataResponse, error)
	AddEntry(ctx context.Context, opts ...grpc.CallOption) (GophKeeper_AddEntryClient, error)
	GetEntry(ctx context.Context, in *GetEntryRequest, opts ...grpc.CallOption) (GophKeeper_GetEntryClient, error)
	UpdateEntry(ctx context.Context, opts ...grpc.CallOption) (GophKeeper_UpdateEntryClient, error)
	DeleteEntry(ctx context.Context, in *DeleteEntryRequest, opts ...grpc.CallOption) (*DeleteEntryResponse, error)
}

type gophKeeperClient struct {
	cc grpc.ClientConnInterface
}

func NewGophKeeperClient(cc grpc.ClientConnInterface) GophKeeperClient {
	return &gophKeeperClient{cc}
}

func (c *gophKeeperClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	err := c.cc.Invoke(ctx, GophKeeper_Register_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gophKeeperClient) Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error) {
	out := new(LoginResponse)
	err := c.cc.Invoke(ctx, GophKeeper_Login_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gophKeeperClient) UpdatePass(ctx context.Context, in *UpdatePassRequest, opts ...grpc.CallOption) (*UpdatePassResponse, error) {
	out := new(UpdatePassResponse)
	err := c.cc.Invoke(ctx, GophKeeper_UpdatePass_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gophKeeperClient) GetMetadata(ctx context.Context, in *GetMetadataRequest, opts ...grpc.CallOption) (*GetMetadataResponse, error) {
	out := new(GetMetadataResponse)
	err := c.cc.Invoke(ctx, GophKeeper_GetMetadata_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gophKeeperClient) AddEntry(ctx context.Context, opts ...grpc.CallOption) (GophKeeper_AddEntryClient, error) {
	stream, err := c.cc.NewStream(ctx, &GophKeeper_ServiceDesc.Streams[0], GophKeeper_AddEntry_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &gophKeeperAddEntryClient{stream}
	return x, nil
}

type GophKeeper_AddEntryClient interface {
	Send(*AddEntryRequest) error
	CloseAndRecv() (*AddEntryResponse, error)
	grpc.ClientStream
}

type gophKeeperAddEntryClient struct {
	grpc.ClientStream
}

func (x *gophKeeperAddEntryClient) Send(m *AddEntryRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *gophKeeperAddEntryClient) CloseAndRecv() (*AddEntryResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(AddEntryResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *gophKeeperClient) GetEntry(ctx context.Context, in *GetEntryRequest, opts ...grpc.CallOption) (GophKeeper_GetEntryClient, error) {
	stream, err := c.cc.NewStream(ctx, &GophKeeper_ServiceDesc.Streams[1], GophKeeper_GetEntry_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &gophKeeperGetEntryClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type GophKeeper_GetEntryClient interface {
	Recv() (*GetEntryResponse, error)
	grpc.ClientStream
}

type gophKeeperGetEntryClient struct {
	grpc.ClientStream
}

func (x *gophKeeperGetEntryClient) Recv() (*GetEntryResponse, error) {
	m := new(GetEntryResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *gophKeeperClient) UpdateEntry(ctx context.Context, opts ...grpc.CallOption) (GophKeeper_UpdateEntryClient, error) {
	stream, err := c.cc.NewStream(ctx, &GophKeeper_ServiceDesc.Streams[2], GophKeeper_UpdateEntry_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &gophKeeperUpdateEntryClient{stream}
	return x, nil
}

type GophKeeper_UpdateEntryClient interface {
	Send(*UpdateEntryRequest) error
	Recv() (*UpdateEntryResponse, error)
	grpc.ClientStream
}

type gophKeeperUpdateEntryClient struct {
	grpc.ClientStream
}

func (x *gophKeeperUpdateEntryClient) Send(m *UpdateEntryRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *gophKeeperUpdateEntryClient) Recv() (*UpdateEntryResponse, error) {
	m := new(UpdateEntryResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *gophKeeperClient) DeleteEntry(ctx context.Context, in *DeleteEntryRequest, opts ...grpc.CallOption) (*DeleteEntryResponse, error) {
	out := new(DeleteEntryResponse)
	err := c.cc.Invoke(ctx, GophKeeper_DeleteEntry_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GophKeeperServer is the server API for GophKeeper service.
// All implementations must embed UnimplementedGophKeeperServer
// for forward compatibility
type GophKeeperServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	Login(context.Context, *LoginRequest) (*LoginResponse, error)
	UpdatePass(context.Context, *UpdatePassRequest) (*UpdatePassResponse, error)
	GetMetadata(context.Context, *GetMetadataRequest) (*GetMetadataResponse, error)
	AddEntry(GophKeeper_AddEntryServer) error
	GetEntry(*GetEntryRequest, GophKeeper_GetEntryServer) error
	UpdateEntry(GophKeeper_UpdateEntryServer) error
	DeleteEntry(context.Context, *DeleteEntryRequest) (*DeleteEntryResponse, error)
	mustEmbedUnimplementedGophKeeperServer()
}

// UnimplementedGophKeeperServer must be embedded to have forward compatible implementations.
type UnimplementedGophKeeperServer struct {
}

func (UnimplementedGophKeeperServer) Register(context.Context, *RegisterRequest) (*RegisterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedGophKeeperServer) Login(context.Context, *LoginRequest) (*LoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedGophKeeperServer) UpdatePass(context.Context, *UpdatePassRequest) (*UpdatePassResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePass not implemented")
}
func (UnimplementedGophKeeperServer) GetMetadata(context.Context, *GetMetadataRequest) (*GetMetadataResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMetadata not implemented")
}
func (UnimplementedGophKeeperServer) AddEntry(GophKeeper_AddEntryServer) error {
	return status.Errorf(codes.Unimplemented, "method AddEntry not implemented")
}
func (UnimplementedGophKeeperServer) GetEntry(*GetEntryRequest, GophKeeper_GetEntryServer) error {
	return status.Errorf(codes.Unimplemented, "method GetEntry not implemented")
}
func (UnimplementedGophKeeperServer) UpdateEntry(GophKeeper_UpdateEntryServer) error {
	return status.Errorf(codes.Unimplemented, "method UpdateEntry not implemented")
}
func (UnimplementedGophKeeperServer) DeleteEntry(context.Context, *DeleteEntryRequest) (*DeleteEntryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteEntry not implemented")
}
func (UnimplementedGophKeeperServer) mustEmbedUnimplementedGophKeeperServer() {}

// UnsafeGophKeeperServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to GophKeeperServer will
// result in compilation errors.
type UnsafeGophKeeperServer interface {
	mustEmbedUnimplementedGophKeeperServer()
}

func RegisterGophKeeperServer(s grpc.ServiceRegistrar, srv GophKeeperServer) {
	s.RegisterService(&GophKeeper_ServiceDesc, srv)
}

func _GophKeeper_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GophKeeperServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GophKeeper_Register_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GophKeeperServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GophKeeper_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GophKeeperServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GophKeeper_Login_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GophKeeperServer).Login(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GophKeeper_UpdatePass_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdatePassRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GophKeeperServer).UpdatePass(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GophKeeper_UpdatePass_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GophKeeperServer).UpdatePass(ctx, req.(*UpdatePassRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GophKeeper_GetMetadata_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetMetadataRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GophKeeperServer).GetMetadata(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GophKeeper_GetMetadata_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GophKeeperServer).GetMetadata(ctx, req.(*GetMetadataRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GophKeeper_AddEntry_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(GophKeeperServer).AddEntry(&gophKeeperAddEntryServer{stream})
}

type GophKeeper_AddEntryServer interface {
	SendAndClose(*AddEntryResponse) error
	Recv() (*AddEntryRequest, error)
	grpc.ServerStream
}

type gophKeeperAddEntryServer struct {
	grpc.ServerStream
}

func (x *gophKeeperAddEntryServer) SendAndClose(m *AddEntryResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *gophKeeperAddEntryServer) Recv() (*AddEntryRequest, error) {
	m := new(AddEntryRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _GophKeeper_GetEntry_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetEntryRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(GophKeeperServer).GetEntry(m, &gophKeeperGetEntryServer{stream})
}

type GophKeeper_GetEntryServer interface {
	Send(*GetEntryResponse) error
	grpc.ServerStream
}

type gophKeeperGetEntryServer struct {
	grpc.ServerStream
}

func (x *gophKeeperGetEntryServer) Send(m *GetEntryResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _GophKeeper_UpdateEntry_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(GophKeeperServer).UpdateEntry(&gophKeeperUpdateEntryServer{stream})
}

type GophKeeper_UpdateEntryServer interface {
	Send(*UpdateEntryResponse) error
	Recv() (*UpdateEntryRequest, error)
	grpc.ServerStream
}

type gophKeeperUpdateEntryServer struct {
	grpc.ServerStream
}

func (x *gophKeeperUpdateEntryServer) Send(m *UpdateEntryResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *gophKeeperUpdateEntryServer) Recv() (*UpdateEntryRequest, error) {
	m := new(UpdateEntryRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _GophKeeper_DeleteEntry_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteEntryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GophKeeperServer).DeleteEntry(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GophKeeper_DeleteEntry_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GophKeeperServer).DeleteEntry(ctx, req.(*DeleteEntryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// GophKeeper_ServiceDesc is the grpc.ServiceDesc for GophKeeper service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var GophKeeper_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.GophKeeper",
	HandlerType: (*GophKeeperServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Register",
			Handler:    _GophKeeper_Register_Handler,
		},
		{
			MethodName: "Login",
			Handler:    _GophKeeper_Login_Handler,
		},
		{
			MethodName: "UpdatePass",
			Handler:    _GophKeeper_UpdatePass_Handler,
		},
		{
			MethodName: "GetMetadata",
			Handler:    _GophKeeper_GetMetadata_Handler,
		},
		{
			MethodName: "DeleteEntry",
			Handler:    _GophKeeper_DeleteEntry_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "AddEntry",
			Handler:       _GophKeeper_AddEntry_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "GetEntry",
			Handler:       _GophKeeper_GetEntry_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "UpdateEntry",
			Handler:       _GophKeeper_UpdateEntry_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "pkg/gophkeeper.proto",
}