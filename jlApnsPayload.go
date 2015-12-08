package jlApns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
)

type AlertDictionary struct {
	Title        string   `json:"title,omitempty"`
	Body         string   `json:"body,omitempty"`
	TitleLocKey  string   `json:"title-loc-key,omitempty"`
	TitleLocArgs []string `json:"title-loc-args,omitempty"`
	ActionLocKey string   `json:"action-loc-key,omitempty"`
	LocKey       string   `json:"loc-key,omitempty"`
	LocArgs      []string `json:"loc-args,omitempty"`
	LaunchImage  string   `json:"launch-image,omitempty"`
}

type Payload struct {
	Alert            interface{} `json:"alert,omitempty"`
	Badge            int         `json:"badge,omitempty"`
	Sound            string      `json:"sound,omitempty"`
	ContentAvailable int         `json:"content-available,omitempty"`
	Category         string      `json:"category,omitempty"`
}

func NewPayload(Alert interface{}, Badge int, Sound string) *Payload {
	return &Payload{Alert: Alert, Badge: Badge, Sound: Sound}
}

func (p *Payload) toJsonData() ([]byte, error) {
	return json.Marshal(map[string]interface{}{"aps": p})
}

type FailInfo struct {
	Pid  uint32
	Code uint8
}

func NewFailInfoFromByte(data []byte) *FailInfo {
	if len(data) != 6 || data[0] != 8 {
		return nil
	}
	buf := bytes.NewReader(data[2:6])
	var value uint32
	binary.Read(buf, binary.LittleEndian, &value)
	return &FailInfo{Pid: value, Code: uint8(data[1])}
}

const (
	deviceTokenItemid            = 1
	payloadItemid                = 2
	notificationIdentifierItemid = 3
	expirationDateItemid         = 4
	priorityItemid               = 5
)

type PushNotificationReq struct {
	Tokens  []string
	payload *Payload
	Expiry  uint32 `json:",omitempty"`
}

func EncodePushNotificationToData(identifier int32, expiry uint32, tokenString string, payloadData []byte, priority uint8) ([]byte, error) {
	token, err := hex.DecodeString(tokenString)
	if err != nil {
		return nil, err
	}
	if len(token) != 32 {
		return nil, errors.New("device token has incorrect length")
	}
	if len(payloadData) > 2048 {
		payloadData = payloadData[:2048]
	}

	// 1+4+ (1+2+32) + (1+2+len(payloadData)) + (1+2+4) + (1+2+4) + (1+2+1)
	totolLen := 1 + 4 + (1 + 2 + 32) + (1 + 2 + len(payloadData)) + (1 + 2 + 4) + (1 + 2 + 4) + (1 + 2 + 1)
	buf := make([]byte, 0, totolLen)
	frameBuffer := bytes.NewBuffer(buf)
	binary.Write(frameBuffer, binary.BigEndian, uint8(2))
	binary.Write(frameBuffer, binary.BigEndian, uint32(totolLen-5))

	binary.Write(frameBuffer, binary.BigEndian, uint8(deviceTokenItemid))
	binary.Write(frameBuffer, binary.BigEndian, uint16(32))
	binary.Write(frameBuffer, binary.BigEndian, token)

	binary.Write(frameBuffer, binary.BigEndian, uint8(payloadItemid))
	binary.Write(frameBuffer, binary.BigEndian, uint16(len(payloadData)))
	binary.Write(frameBuffer, binary.BigEndian, payloadData)

	binary.Write(frameBuffer, binary.BigEndian, uint8(notificationIdentifierItemid))
	binary.Write(frameBuffer, binary.BigEndian, uint16(4))
	binary.Write(frameBuffer, binary.BigEndian, uint32(identifier))

	binary.Write(frameBuffer, binary.BigEndian, uint8(expirationDateItemid))
	binary.Write(frameBuffer, binary.BigEndian, uint16(4))
	binary.Write(frameBuffer, binary.BigEndian, uint32(expiry))

	binary.Write(frameBuffer, binary.BigEndian, uint8(priorityItemid))
	binary.Write(frameBuffer, binary.BigEndian, uint16(1))
	binary.Write(frameBuffer, binary.BigEndian, uint8(priority))

	buf = frameBuffer.Bytes()
	if len(buf) != totolLen {
		log.Printf("unknown bug for encode length:%d vs %d", len(buf), totolLen)
		return nil, errors.New("unknown bug for encode length")
	}

	return buf, nil
}
