package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net/smtp"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/scrypt"
)

// función para comprobar errores (ahorra escritura)
func check(e error) {
	if e != nil {
		fmt.Println(e.Error())
	}
}

func createJWTUser(username string) string {
	//UserStruct para el token
	type UserStruct struct {
		Username string `json:"username"`
		jwt.StandardClaims
	}
	// Embed User information to `token`
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS512"), &UserStruct{Username: username})

	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	claims["iat"] = time.Now().Unix()
	claims["aud"] = username
	token.Claims = claims
	// token -> string. Only server knows this secret (foobar).
	clavemaestra, err := getTokenKey(rutaMasterKey)
	check(err)
	tokenstring, err := token.SignedString([]byte(clavemaestra))
	check(err)
	return tokenstring
}

func validarTokenUser(tokenRecibido string, username string) bool {
	clavemaestra, err := getTokenKey(rutaMasterKey)
	check(err)
	token, err := jwt.Parse(tokenRecibido, func(token *jwt.Token) (interface{}, error) {
		return []byte(clavemaestra), nil
	})

	if err != nil || token == nil { //ya valida tanto el tiempo de expiracion como si se ha firmado bien etc
		log.Println("Token incorrecto")
		return false
	}

	//claims := make(jwt.MapClaims)
	claims := token.Claims.(jwt.MapClaims)
	if claims["aud"].(string) != username {
		log.Println("Usuario de token incorrecto")
		return false
	}

	tokenEncontrado := false
	for i := 0; i < len(users.Users) && !tokenEncontrado; i++ {
		if username == users.Users[i].User && tokenRecibido == users.Users[i].Token {
			tokenEncontrado = true
		}
	}
	return tokenEncontrado
}

// Devuelve el string de la cadena encriptada
func encriptarScrypt(cadena string, seed string) string {
	salt := []byte(seed)

	dk, err := scrypt.Key([]byte(cadena), salt, 1<<15, 10, 1, 32)
	check(err)
	return base64.StdEncoding.EncodeToString(dk)
}

func encodeURLB64(cadena string) string {
	return base64.URLEncoding.EncodeToString([]byte(cadena))
}

func decodeURLB64(cadena string) string {
	decode, _ := base64.URLEncoding.DecodeString(cadena)
	return string(decode[:])
}

func randomString(n int) string {
	const randomStringLetters = "0123abcdefghijklmnopqrstuvwxyz456ABCDEFGHIJKLMNOPQRSTUVWXYZ789"
	b := make([]byte, n)
	for i := range b {
		b[i] = randomStringLetters[mathrand.Intn(len(randomStringLetters))]
	}
	return string(b)
}

//Comprueba que los directorios no existen
func createDirIfNotExist(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0766)
		if err != nil {
			panic(err)
		}
	}
}

func decryptAESCFB(data []byte, keystring string) []byte {
	ciphertext := data
	key := []byte(keystring)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(errors.New("La contraseña en AES tiene que ser exactamente de 16, 24, o 32 bytes"))
	}
	if len(ciphertext) < aes.BlockSize {
		panic(errors.New("El texto a descifrar tiene que tener al menos 16 bytes"))
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext
}

func encryptAESCFB(data []byte, keystring string) []byte {
	plaintext := data
	key := []byte(keystring)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(errors.New("La contraseña en AES tiene que ser exactamente de 16, 24, o 32 bytes"))
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(errors.New("El texto a descifrar tiene que tener al menos 16 bytes"))
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func hashSHA512(datos []byte) [64]byte {
	return sha512.Sum512(datos)
}

func deleteFile(path string) {
	os.Remove(path)
}

func getUser(user string) int {
	for i := 0; i < len(users.Users); i++ {
		if users.Users[i].User == user {
			return i
		}
	}
	return -1
}

func leerArchivo(ruta string) []byte {
	// Abre el archivo json
	archivo, err := os.Open(ruta)
	// if we os.Open returns an error then handle it
	if err != nil {
		//fmt.Println(err)
		// detect if file exists
		var _, err = os.Stat(ruta)

		// create file if not exists
		if os.IsNotExist(err) {
			var file, err = os.Create(ruta)
			check(err)
			defer file.Close()
		}

		log.Println("Se ha creado correctamente el fichero: ", ruta)
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer archivo.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(archivo)
	return byteValue
}

func escribirArchivo(ruta string, content []byte) {
	f, err := os.OpenFile(ruta, os.O_WRONLY|os.O_CREATE, 0766)
	defer f.Close()
	check(err)
	io.Copy(f, bytes.NewReader(content))
}

//PasswordStruct struct para passwords
type PasswordStruct struct {
	Master string `json:"master"`
	Token  string `json:"token"`
	Email  string `json:"email"`
}

func getMasterKey(path string) (string, error) {
	jsonBytes := leerArchivo(path)
	var password PasswordStruct
	err := json.Unmarshal(jsonBytes, &password)
	check(err)
	if password.Master != "" {
		return password.Master, nil
	}
	return "", errors.New("Error al obtener la contraseña maestra")
}

func getEmailKey(path string) (string, error) {
	jsonBytes := leerArchivo(path)
	var password PasswordStruct
	err := json.Unmarshal(jsonBytes, &password)
	check(err)
	if password.Email != "" {
		return password.Email, nil
	}
	return "", errors.New("Error al obtener la contraseña del email")
}

func getTokenKey(path string) (string, error) {
	jsonBytes := leerArchivo(path)
	var password PasswordStruct
	err := json.Unmarshal(jsonBytes, &password)
	check(err)
	if password.Token != "" {
		return password.Token, nil
	}
	return "", errors.New("Error al obtener la contraseña del token")
}

func sendEmail(codigo string, destinatario string) {
	from := "gintonico.sds@gmail.com"
	pass, err := getEmailKey(rutaMasterKey)
	check(err)
	to := destinatario
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"

	msg := "From: " + from + "\n" + "To: " + to + "\n" +
		"Subject: Gintónico: Confirmar autenticación\n" + mime + email(codigo)

	err = smtp.SendMail("smtp.gmail.com:587", smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("Error smtp gmail: %s", err)
		return
	}
	log.Println("Email enviado a: " + destinatario)
}

func email(codigo string) string {
	return `<!doctype html>
	<html style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
	
	<head>
	  	<meta name="viewport" content="width=device-width" />
	  	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	  	<title>Gintónico: Confirmar autenticación</title>
	
	  	<style type="text/css">
			img {
				max-width: 100%;
			}
			body {
				-webkit-font-smoothing: antialiased;
				-webkit-text-size-adjust: none;
				width: 100% !important;
				height: 100%;
				line-height: 1.6em;
				background-color: #f6f6f6;
			}
			@media only screen and (max-width: 640px) {
				body {
					padding: 0 !important;
				}
				h1 {
					font-weight: 800 !important;
					margin: 20px 0 5px !important;
					font-size: 22px !important;
				}
				h2 {
					font-weight: 800 !important;
					margin: 20px 0 5px !important;
					font-size: 18px !important;
				}
				h3 {
					font-weight: 800 !important;
					margin: 20px 0 5px !important;
					font-size: 16px !important;
				}
				h4 {
					font-weight: 800 !important;
					margin: 20px 0 5px !important;
				}
				.container {
					padding: 0 !important;
					width: 100% !important;
				}
				.content {
					padding: 0 !important;
				}
				.content-wrap {
					padding: 10px !important;
				}
				.invoice {
					width: 100% !important;
				}
			}
	  </style>
	</head>
	
	<body style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; -webkit-font-smoothing: antialiased; -webkit-text-size-adjust: none; width: 100% !important; height: 100%; line-height: 1.6em; background-color: #f6f6f6; margin: 0;" bgcolor="#f6f6f6">
		<table class="body-wrap" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; width: 100%; background-color: #f6f6f6; margin: 0;" bgcolor="#f6f6f6">
			<tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
				<td style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0;" valign="top"></td>
				<td class="container" width="600" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; display: block !important; max-width: 600px !important; clear: both !important; margin: 0 auto;" valign="top">
					<div class="content" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; max-width: 600px; display: block; margin: 0 auto; padding: 20px;">
						<table class="main" width="100%" cellpadding="0" cellspacing="0" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; border-radius: 3px; background-color: #fff; margin: 0; border: 1px solid #e9e9e9;" bgcolor="#fff">
							<tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
								<td class="alert alert-warning" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 16px; vertical-align: top; color: #fff; font-weight: 500; text-align: center; border-radius: 3px 3px 0 0; background-color: #FF654E; margin: 0; padding: 20px;" align="center" bgcolor="#FF654E" valign="top">
									Gintónico, Doble factor de autenticación.
								</td>
							</tr>
							<tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
								<td class="content-wrap" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 20px;" valign="top">
									<table width="100%" cellpadding="0" cellspacing="0" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
										<tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
											<td class="content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
												Recientemente se ha intentado acceder a tu cuenta de Gintónico con tu usuario y
												<strong style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">contraseña</strong>.
											</td>
										</tr>
										<tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
											<td class="content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
												Si has sido tú, introduce el código siguiente en el programa e inicia sesión con normalidad.
												</br>
												Si no has sido tú, cambia tus credenciales lo más rápido posible y/o contacta con algún administrador.
											</td>
										</tr>
										<tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
											<td class="content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
												<p style="width:100%; text-align: center; letter-spacing: 1.5px; color: #53A3CD; font-weight: 700;font-size: 2em;">
													` + codigo + `
												</p>
											</td>
										</tr>
										<tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
											<td class="content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0; padding: 0 0 20px;" valign="top">
												Gracias por escoger ©Gintónico.
											</td>
										</tr>
									</table>
								</td>
							</tr>
						</table>
						<div class="footer" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; width: 100%; clear: both; color: #999; margin: 0; padding: 20px;">
							<table width="100%" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
								<tr style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; margin: 0;">
									<td class="aligncenter content-block" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 12px; vertical-align: top; color: #999; text-align: center; margin: 0; padding: 0 0 20px;" align="center" valign="top">
										<a href="#" style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 12px; color: #999; text-decoration: underline; margin: 0;">
											Desuscríbete
										</a> de estas alertas.
									</td>
								</tr>
							</table>
						</div>
					</div>
				</td>
				<td style="font-family: 'Helvetica Neue',Helvetica,Arial,sans-serif; box-sizing: border-box; font-size: 14px; vertical-align: top; margin: 0;" valign="top"></td>
			</tr>
		</table>
	</body>
	</html>`
}
