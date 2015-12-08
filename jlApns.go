package jlApns

// doc: https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/CommunicatingWIthAPS.html

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
	"time"
)

const (
	StateDisconnect = iota
	StateConncting
	StateConncted
)

var ApplePushResponses = map[uint8]string{
	0:   "NO_ERRORS",
	1:   "PROCESSING_ERROR",
	2:   "MISSING_DEVICE_TOKEN",
	3:   "MISSING_TOPIC",
	4:   "MISSING_PAYLOAD",
	5:   "INVALID_TOKEN_SIZE",
	6:   "INVALID_TOPIC_SIZE",
	7:   "INVALID_PAYLOAD_SIZE",
	8:   "INVALID_TOKEN",
	10:  "SHUTDOWN",
	255: "UNKNOWN",
}

type APNSession struct {
	Gateway         string // APNS gateway
	CertificateFile string
	KeyFile         string

	CertificateBase64 string
	KeyBase64         string

	conn         net.Conn
	tlsConn      *tls.Conn
	ResponseChan chan *FailInfo

	state int
}

func (a *APNSession) State() int {
	return a.state
}
func NewAPNSession(gateway, certificateFile, keyFile string, responseChan chan *FailInfo) (a *APNSession) {
	a = new(APNSession)
	a.Gateway = gateway
	a.CertificateFile = certificateFile
	a.KeyFile = keyFile
	a.state = StateDisconnect
	a.ResponseChan = responseChan
	return
}

// ----------
func (a *APNSession) Send(sendIdentifier int32, payload *Payload, token string, expiration uint32) error {
	if payload == nil || len(token) != 32*2 {
		return errors.New("Invalid args")
	}
	if a.state != StateConncted {
		return errors.New("Not Connect")
	}
	payloadData, err := payload.toJsonData()
	if err != nil {
		return err
	}

	buf, err := EncodePushNotificationToData(sendIdentifier, expiration, token, payloadData, 10)
	if err != nil {
		return err
	}
	_, err = a.tlsConn.Write(buf)
	if err != nil {
		return err
	}

	return nil
}

func (a *APNSession) RecvRespnose() {
	if a.ResponseChan == nil || a.state != StateConncted {
		return
	}
	buffer := make([]byte, 6, 6)
	for {
		readCount, err := a.tlsConn.Read(buffer)
		if err == nil && buffer[0] == 8 {
			log.Printf("send data len:%d\n", readCount)
			info := NewFailInfoFromByte(buffer)
			if info.Code == 10 {
				a.Close()
				break
			}
			if info != nil && a.ResponseChan != nil {
				a.ResponseChan <- info
			}

		} else {
			log.Printf("send data err:%v\n", err)
			a.Close()
			break
		}
	}

}

// ----------

func (a *APNSession) Close() {
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}

	if a.tlsConn != nil {
		a.tlsConn.Close()
		a.tlsConn = nil
	}
}

func (a *APNSession) Connect() (err error) {
	if a.state != StateDisconnect {
		if a.state == StateConncted {
			return
		}
		return errors.New("connecting")
	}
	a.state = StateConncting
	defer func() {
		if err == nil {
			a.state = StateConncted
		} else {
			a.state = StateDisconnect
		}
	}()

	var cert tls.Certificate
	if len(a.CertificateBase64) == 0 || len(a.KeyBase64) == 0 {
		// The user did not specify raw block contents, so check the filesystem.
		cert, err = tls.LoadX509KeyPair(a.CertificateFile, a.KeyFile)
	} else {
		// The user provided the raw block contents, so use that.
		cert, err = tls.X509KeyPair([]byte(a.CertificateBase64), []byte(a.KeyBase64))
	}
	if err != nil {
		return err
	}

	gatewayParts := strings.Split(a.Gateway, ":")
	if len(gatewayParts) != 2 {
		return errors.New("Invalid args")
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   gatewayParts[0],
	}

	conncetedChannel := make(chan error, 1)
	go func() {
		a.conn, err = net.Dial("tcp", a.Gateway)
		if err != nil {
			a.conn = nil
		}
		conncetedChannel <- err
	}()
	select {
	case e := <-conncetedChannel:
		if e != nil {
			err = e
		}
	case <-time.After(time.Second * 20):
		err = errors.New("Timeout connect")
	}
	if err != nil {
		return err
	}

	go func() {
		a.tlsConn = tls.Client(a.conn, conf)
		err = a.tlsConn.Handshake()
		if err != nil {
			a.tlsConn.Close()
			a.tlsConn = nil
		}
		conncetedChannel <- err
	}()
	select {
	case e := <-conncetedChannel:
		if e != nil {
			err = e
		}
	case <-time.After(time.Second * 20):
		err = errors.New("Timeout Handshake")
	}
	if err != nil {
		return err
	}

	log.Printf("Connect success\n")

	if a.ResponseChan != nil {
		go a.RecvRespnose()
	}

	return

}
