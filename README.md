# jlApns
apns with golang


### How to Use:

```bash
go get github.com/wneo/jlApns
```

#### simple use:

```go
  responseChan := make(chan *jlApns.FailInfo, 100)
	session := jlApns.NewAPNSession("gateway.sandbox.push.apple.com:2195", "path To Cert.pem", "path To  Key-noenc.pem", responseChan)

	err := session.Connect()
	if err != nil {
		log.Println("Error to conncet:", err)
		return
	}
	payload := jlApns.NewPayload("Hello APNs", 3, "")

	for i := 0; i < 50; i++ {
		payload.Alert = fmt.Sprintf("Hello APNs index:%d", i)
		log.Printf("To send index %d", i)
		err = session.Send(int32(i), payload, "TokenString...", 0)
		if err != nil {
			log.Println("Error to Send:", err)
			break
		} else {
			log.Printf("Send success")
		}
		log.Printf("sended index %d", i)
	}
	for {
		r := <-responseChan
		log.Printf("%v", r)
	}

	session.Close()
```

### License

This software is released under the MIT License, see LICENSE.txt.
