package main

import (
	"bytes"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
)

// función para comprobar errores (ahorra escritura)
func check(e error) {
	if e != nil {
		fmt.Println(e.Error())
	}
}

func sendServerPetition(method string, datos io.Reader, route string, contentType string) *http.Response {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(method, "https://localhost:8081"+route, datos)
	req.Header.Set("Content-Type", contentType)
	req.Header.Add("Username", login)
	req.Header.Add("Authorization", token)
	r, err := client.Do(req)

	check(err)
	return r
}

func encodeURLB64(cadena string) string {
	return base64.URLEncoding.EncodeToString([]byte(cadena))
}

func decodeURLB64(cadena string) string {
	decode, _ := base64.URLEncoding.DecodeString(cadena)
	return string(decode[:])
}

func hashSHA512(datos []byte) []byte {
	hash := sha512.Sum512(datos)
	return hash[:]
}

func streamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.String()
}

func createFile(path string) {
	// detect if file exists
	//var _, err = os.Stat(path)

	// create file if not exists
	var file, err = os.Create(path)
	check(err)
	defer file.Close()

}

func writeFile(path string, content string) {
	// open file using READ & WRITE permission
	var file, err = os.OpenFile(path, os.O_RDWR, 0666)
	check(err)
	defer file.Close()

	// write some text line-by-line to file
	_, err = file.WriteString(content)

	err = file.Sync()
	check(err)
}

func createDirIfNotExist(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0766)
		if err != nil {
			panic(err)
		}
	}
}

func formatBytesToString(b int) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	format := [...]string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), format[exp])
}
