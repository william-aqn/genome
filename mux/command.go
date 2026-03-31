// Package mux implements stream multiplexing over a single transport connection.
// It provides reliable, ordered delivery with flow control and congestion control,
// similar to TCP-over-UDP.
package mux

import (
	"encoding/binary"
	"fmt"
	"io"
)

// CmdType identifies the type of a multiplexor command.
type CmdType uint8

const (
	CmdOpen  CmdType = 0x01 // open a new stream to a destination
	CmdData  CmdType = 0x02 // data for an existing stream
	CmdClose CmdType = 0x03 // close a stream
	CmdAck   CmdType = 0x04 // acknowledgment with flow control
)

// SACKBlock represents a selective acknowledgment range [Left, Right).
type SACKBlock struct {
	Left  uint32
	Right uint32
}

// Command is the inner (plaintext) frame carried inside the encrypted tunnel payload.
type Command struct {
	Type     CmdType
	StreamID uint32
	Seq      uint32      // for DATA: sequence number
	AckSeq   uint32      // for ACK: cumulative acknowledgment
	SACKs    []SACKBlock // for ACK: selective ack blocks
	Window   uint32      // for ACK: receive window in bytes
	DestAddr string      // for OPEN: target address
	DestPort uint16      // for OPEN: target port
	Data     []byte      // for DATA: payload bytes
}

// Wire format (inside encrypted payload):
// [CmdType: 1][StreamID: 4][...type-specific...]
//
// DATA:  [0x02][StreamID:4][Seq:4][Data:rest]
// ACK:   [0x04][StreamID:4][AckSeq:4][Window:4][NumSACK:2][SACKBlocks:8*N]
// OPEN:  [0x01][StreamID:4][Port:2][AddrLen:2][Addr:variable]
// CLOSE: [0x03][StreamID:4]

// EncodeCommand serializes a Command into bytes.
func EncodeCommand(cmd *Command) ([]byte, error) {
	switch cmd.Type {
	case CmdOpen:
		return encodeOpen(cmd)
	case CmdData:
		return encodeData(cmd)
	case CmdClose:
		return encodeClose(cmd)
	case CmdAck:
		return encodeAck(cmd)
	default:
		return nil, fmt.Errorf("mux: unknown command type 0x%02x", cmd.Type)
	}
}

// DecodeCommand deserializes a Command from bytes.
func DecodeCommand(data []byte) (*Command, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("mux: command too short (%d bytes)", len(data))
	}
	cmd := &Command{
		Type:     CmdType(data[0]),
		StreamID: binary.BigEndian.Uint32(data[1:5]),
	}
	rest := data[5:]

	switch cmd.Type {
	case CmdOpen:
		return decodeOpen(cmd, rest)
	case CmdData:
		return decodeData(cmd, rest)
	case CmdClose:
		return cmd, nil
	case CmdAck:
		return decodeAck(cmd, rest)
	default:
		return nil, fmt.Errorf("mux: unknown command type 0x%02x", cmd.Type)
	}
}

func encodeOpen(cmd *Command) ([]byte, error) {
	addrBytes := []byte(cmd.DestAddr)
	if len(addrBytes) > 0xFFFF {
		return nil, fmt.Errorf("mux: address too long (%d bytes)", len(addrBytes))
	}
	buf := make([]byte, 1+4+2+2+len(addrBytes))
	buf[0] = byte(CmdOpen)
	binary.BigEndian.PutUint32(buf[1:], cmd.StreamID)
	binary.BigEndian.PutUint16(buf[5:], cmd.DestPort)
	binary.BigEndian.PutUint16(buf[7:], uint16(len(addrBytes)))
	copy(buf[9:], addrBytes)
	return buf, nil
}

func decodeOpen(cmd *Command, rest []byte) (*Command, error) {
	if len(rest) < 4 {
		return nil, fmt.Errorf("mux: OPEN too short")
	}
	cmd.DestPort = binary.BigEndian.Uint16(rest[0:2])
	addrLen := binary.BigEndian.Uint16(rest[2:4])
	if len(rest) < 4+int(addrLen) {
		return nil, fmt.Errorf("mux: OPEN truncated address")
	}
	cmd.DestAddr = string(rest[4 : 4+addrLen])
	return cmd, nil
}

func encodeData(cmd *Command) ([]byte, error) {
	buf := make([]byte, 1+4+4+len(cmd.Data))
	buf[0] = byte(CmdData)
	binary.BigEndian.PutUint32(buf[1:], cmd.StreamID)
	binary.BigEndian.PutUint32(buf[5:], cmd.Seq)
	copy(buf[9:], cmd.Data)
	return buf, nil
}

func decodeData(cmd *Command, rest []byte) (*Command, error) {
	if len(rest) < 4 {
		return nil, fmt.Errorf("mux: DATA too short")
	}
	cmd.Seq = binary.BigEndian.Uint32(rest[0:4])
	cmd.Data = make([]byte, len(rest)-4)
	copy(cmd.Data, rest[4:])
	return cmd, nil
}

func encodeClose(cmd *Command) ([]byte, error) {
	buf := make([]byte, 5)
	buf[0] = byte(CmdClose)
	binary.BigEndian.PutUint32(buf[1:], cmd.StreamID)
	return buf, nil
}

func encodeAck(cmd *Command) ([]byte, error) {
	numSACK := len(cmd.SACKs)
	if numSACK > 0xFFFF {
		return nil, fmt.Errorf("mux: too many SACK blocks (%d)", numSACK)
	}
	buf := make([]byte, 1+4+4+4+2+8*numSACK)
	buf[0] = byte(CmdAck)
	binary.BigEndian.PutUint32(buf[1:], cmd.StreamID)
	binary.BigEndian.PutUint32(buf[5:], cmd.AckSeq)
	binary.BigEndian.PutUint32(buf[9:], cmd.Window)
	binary.BigEndian.PutUint16(buf[13:], uint16(numSACK))
	off := 15
	for _, blk := range cmd.SACKs {
		binary.BigEndian.PutUint32(buf[off:], blk.Left)
		binary.BigEndian.PutUint32(buf[off+4:], blk.Right)
		off += 8
	}
	return buf, nil
}

func decodeAck(cmd *Command, rest []byte) (*Command, error) {
	if len(rest) < 10 {
		return nil, fmt.Errorf("mux: ACK too short")
	}
	cmd.AckSeq = binary.BigEndian.Uint32(rest[0:4])
	cmd.Window = binary.BigEndian.Uint32(rest[4:8])
	numSACK := binary.BigEndian.Uint16(rest[8:10])
	off := 10
	if len(rest) < off+int(numSACK)*8 {
		return nil, fmt.Errorf("mux: ACK truncated SACK blocks")
	}
	cmd.SACKs = make([]SACKBlock, numSACK)
	for i := range cmd.SACKs {
		cmd.SACKs[i].Left = binary.BigEndian.Uint32(rest[off:])
		cmd.SACKs[i].Right = binary.BigEndian.Uint32(rest[off+4:])
		off += 8
	}
	return cmd, nil
}

// WriteCommand writes a command to a writer with a 2-byte length prefix.
func WriteCommand(w io.Writer, cmd *Command) error {
	data, err := EncodeCommand(cmd)
	if err != nil {
		return err
	}
	return writeFrame(w, data)
}

// ReadCommand reads a length-prefixed command from a reader.
func ReadCommand(r io.Reader) (*Command, error) {
	data, err := readFrame(r)
	if err != nil {
		return nil, err
	}
	return DecodeCommand(data)
}

func writeFrame(w io.Writer, data []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}
