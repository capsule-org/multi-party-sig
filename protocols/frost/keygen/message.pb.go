// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: protocols/frost/keygen/message.proto

package keygen

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_taurusgroup_cmp_ecdsa_pkg_math_curve "github.com/taurusgroup/cmp-ecdsa/pkg/math/curve"
	polynomial "github.com/taurusgroup/cmp-ecdsa/pkg/math/polynomial"
	sch "github.com/taurusgroup/cmp-ecdsa/pkg/zk/sch"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Keygen2 struct {
	// Phi_i is the commitment to the polynomial that this participant generated.
	Phi_i *polynomial.Exponent `protobuf:"bytes,1,opt,name=Phi_i,json=PhiI,proto3" json:"Phi_i,omitempty"`
	// Sigma_i is the Schnorr proof of knowledge of the participant's secret
	Sigma_i *sch.Proof `protobuf:"bytes,2,opt,name=Sigma_i,json=SigmaI,proto3" json:"Sigma_i,omitempty"`
}

func (m *Keygen2) Reset()         { *m = Keygen2{} }
func (m *Keygen2) String() string { return proto.CompactTextString(m) }
func (*Keygen2) ProtoMessage()    {}
func (*Keygen2) Descriptor() ([]byte, []int) {
	return fileDescriptor_3e7dc99cae6693b0, []int{0}
}
func (m *Keygen2) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Keygen2) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Keygen2) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Keygen2.Merge(m, src)
}
func (m *Keygen2) XXX_Size() int {
	return m.Size()
}
func (m *Keygen2) XXX_DiscardUnknown() {
	xxx_messageInfo_Keygen2.DiscardUnknown(m)
}

var xxx_messageInfo_Keygen2 proto.InternalMessageInfo

type Keygen3 struct {
	// F_li is the secret share sent from party l to this party.
	F_li *github_com_taurusgroup_cmp_ecdsa_pkg_math_curve.Scalar `protobuf:"bytes,1,opt,name=F_li,json=FLi,proto3,customtype=github.com/taurusgroup/cmp-ecdsa/pkg/math/curve.Scalar" json:"F_li,omitempty"`
}

func (m *Keygen3) Reset()         { *m = Keygen3{} }
func (m *Keygen3) String() string { return proto.CompactTextString(m) }
func (*Keygen3) ProtoMessage()    {}
func (*Keygen3) Descriptor() ([]byte, []int) {
	return fileDescriptor_3e7dc99cae6693b0, []int{1}
}
func (m *Keygen3) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Keygen3) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Keygen3) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Keygen3.Merge(m, src)
}
func (m *Keygen3) XXX_Size() int {
	return m.Size()
}
func (m *Keygen3) XXX_DiscardUnknown() {
	xxx_messageInfo_Keygen3.DiscardUnknown(m)
}

var xxx_messageInfo_Keygen3 proto.InternalMessageInfo

func init() {
	proto.RegisterType((*Keygen2)(nil), "keygen.Keygen2")
	proto.RegisterType((*Keygen3)(nil), "keygen.Keygen3")
}

func init() {
	proto.RegisterFile("protocols/frost/keygen/message.proto", fileDescriptor_3e7dc99cae6693b0)
}

var fileDescriptor_3e7dc99cae6693b0 = []byte{
	// 341 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x91, 0x4f, 0x4b, 0xc3, 0x30,
	0x18, 0xc6, 0x5b, 0x9d, 0x1b, 0x76, 0x3b, 0x95, 0x1d, 0xc6, 0x0e, 0xa9, 0x0c, 0x0f, 0x5e, 0xd6,
	0xc0, 0x26, 0x0a, 0x1e, 0x0b, 0x0e, 0x86, 0x1e, 0xc6, 0xc6, 0x2e, 0x5e, 0x46, 0x16, 0xd3, 0x34,
	0xf4, 0x4f, 0x4a, 0xd2, 0x8a, 0xdb, 0x27, 0xf0, 0xe8, 0x47, 0xf0, 0xe3, 0x78, 0xdc, 0x71, 0x78,
	0x28, 0x92, 0x7d, 0x11, 0x69, 0xba, 0xa9, 0x07, 0xc1, 0x43, 0xe0, 0x7d, 0x9f, 0xf7, 0x79, 0x9f,
	0x1f, 0x49, 0xac, 0xf3, 0x54, 0xf0, 0x8c, 0x63, 0x1e, 0x49, 0xe8, 0x0b, 0x2e, 0x33, 0x18, 0x92,
	0x15, 0x25, 0x09, 0x8c, 0x89, 0x94, 0x88, 0x12, 0x57, 0x8f, 0xed, 0x7a, 0xa5, 0x76, 0xfb, 0x94,
	0x65, 0x41, 0xbe, 0x74, 0x31, 0x8f, 0x21, 0xe5, 0x94, 0x43, 0x3d, 0x5e, 0xe6, 0xbe, 0xee, 0x74,
	0xa3, 0xab, 0x6a, 0xad, 0xdb, 0x4b, 0x43, 0x0a, 0x63, 0x94, 0x05, 0x30, 0xe5, 0xd1, 0x2a, 0xe1,
	0x31, 0x43, 0x11, 0x24, 0xcf, 0x29, 0x4f, 0x48, 0x92, 0xed, 0x3d, 0xed, 0xd2, 0xb3, 0x0e, 0xa1,
	0xc4, 0x41, 0x79, 0x2a, 0xb5, 0xb7, 0xb2, 0x1a, 0x77, 0x1a, 0x39, 0xb0, 0x2f, 0xad, 0x93, 0x49,
	0xc0, 0x16, 0xac, 0x63, 0x9e, 0x99, 0x17, 0xcd, 0x41, 0xdb, 0xfd, 0xc9, 0x72, 0x6f, 0xf7, 0x59,
	0xde, 0xa9, 0x2a, 0x9c, 0xca, 0x36, 0xad, 0x4d, 0x02, 0x36, 0xb6, 0x07, 0x56, 0x63, 0xc6, 0x68,
	0x8c, 0x16, 0xac, 0x73, 0xa4, 0xf7, 0x5a, 0xee, 0x3a, 0x2c, 0xf3, 0x27, 0x82, 0x73, 0xdf, 0x6b,
	0xaa, 0xc2, 0x39, 0x18, 0xa6, 0x75, 0x5d, 0x8c, 0x6f, 0x6a, 0x2f, 0x6f, 0x8e, 0xd1, 0xf3, 0x0f,
	0xe8, 0xa1, 0x3d, 0xb7, 0x6a, 0xa3, 0x45, 0x54, 0x91, 0x5b, 0x9e, 0xf7, 0x51, 0x38, 0x57, 0xbf,
	0x1e, 0x20, 0x43, 0xb9, 0xc8, 0x25, 0x15, 0x3c, 0x4f, 0x21, 0x8e, 0xd3, 0x3e, 0xc1, 0x8f, 0x12,
	0xc1, 0xef, 0x2b, 0xe3, 0x5c, 0x3c, 0x11, 0x77, 0x86, 0x51, 0x84, 0x84, 0x2a, 0x1c, 0x9d, 0x34,
	0x3d, 0x1e, 0xdd, 0xb3, 0x8a, 0xe3, 0xcd, 0xdf, 0x15, 0x30, 0x37, 0x0a, 0x98, 0x5b, 0x05, 0xcc,
	0x4f, 0x05, 0xcc, 0xd7, 0x1d, 0x30, 0x36, 0x3b, 0x60, 0x6c, 0x77, 0xc0, 0x78, 0xb8, 0xfe, 0x1f,
	0xf4, 0xe7, 0xc7, 0x2d, 0xeb, 0x5a, 0x1f, 0x7e, 0x05, 0x00, 0x00, 0xff, 0xff, 0x6f, 0x70, 0x63,
	0x68, 0xd9, 0x01, 0x00, 0x00,
}

func (m *Keygen2) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Keygen2) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Keygen2) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Sigma_i != nil {
		{
			size, err := m.Sigma_i.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Phi_i != nil {
		{
			size, err := m.Phi_i.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Keygen3) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Keygen3) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Keygen3) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.F_li != nil {
		{
			size := m.F_li.Size()
			i -= size
			if _, err := m.F_li.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
			i = encodeVarintMessage(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintMessage(dAtA []byte, offset int, v uint64) int {
	offset -= sovMessage(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Keygen2) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Phi_i != nil {
		l = m.Phi_i.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.Sigma_i != nil {
		l = m.Sigma_i.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func (m *Keygen3) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.F_li != nil {
		l = m.F_li.Size()
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func sovMessage(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMessage(x uint64) (n int) {
	return sovMessage(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Keygen2) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Keygen2: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Keygen2: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Phi_i", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Phi_i == nil {
				m.Phi_i = &polynomial.Exponent{}
			}
			if err := m.Phi_i.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Sigma_i", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Sigma_i == nil {
				m.Sigma_i = &sch.Proof{}
			}
			if err := m.Sigma_i.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Keygen3) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Keygen3: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Keygen3: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field F_li", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var v github_com_taurusgroup_cmp_ecdsa_pkg_math_curve.Scalar
			m.F_li = &v
			if err := m.F_li.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMessage(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMessage
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMessage
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMessage
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMessage        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMessage          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMessage = fmt.Errorf("proto: unexpected end of group")
)