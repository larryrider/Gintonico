package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/kabukky/httpscerts"
)

// respuesta del servidor
type resp struct {
	Ok  bool   `json:"ok"`  // true -> correcto, false -> error
	Msg string `json:"msg"` // mensaje adicional
}

// Users Estructura de usuarios
type Users struct {
	Users []User `json:"users"`
}

// User Estructura de usuario
type User struct {
	User          string `json:"user"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	Salt          string `json:"salt"`
	Cifrado       string `json:"cifrado"`
	Token         string `json:"token"`
	FactorEnabled bool   `json:"factorEnabled"`
	FactorCode    string `json:"factorCode"`
	FactorExp     string `json:"factorExp"`
}

// Block Estructura de bloque
type Block struct {
	Block string `json:"block"`
	Hash  string `json:"hash"`
	User  string `json:"user"`
}

// Blocks Estructura de bloque
type Blocks struct {
	Blocks []Block `json:"blocks"`
}

//BlockPosition Posicion del bloque
type BlockPosition struct {
	Block    string `json:"block"`
	Position string `json:"position"`
	Size     string `json:"size"`
}

// File Estructura de file
type File struct {
	User  string          `json:"user"`
	File  string          `json:"file"`
	Order []BlockPosition `json:"order"`
}

//Files estructura de files
type Files struct {
	Files []File `json:"files"`
}

var users *Users
var files *Files
var blocks *Blocks

const rutaMasterKey = "./master.key"
const rutaLog = "./log.txt"
const rutaArchivos = "./archivos/"
const rutaCertificados = "./certificados"
const rutaDatabases = "./databases"
const rutaUsersBD = rutaDatabases + "/users.json"
const rutaBlocksBD = rutaDatabases + "/blocks.json"
const rutaFilesBD = rutaDatabases + "/files.json"

// Función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}
	rJSON, err := json.Marshal(&r)
	check(err)
	w.Write(rJSON)
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://127.0.0.1:8081"+r.RequestURI, http.StatusMovedPermanently)
}

func handler(w http.ResponseWriter, r *http.Request) {
	response(w, true, "Bienvenido a Gintónico")
}

// Función handler llamada cuando un usuario
// realiza una petición de login.
func handlerLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()                                // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	body := buf.Bytes()

	type LoginJSON struct {
		Login    []string `json:"login"`
		Password []string `json:"password"`
	}
	var user LoginJSON
	err := json.Unmarshal(body, &user)
	check(err)

	posicionUser := getUser(user.Login[0])
	if posicionUser >= 0 {
		loginOK, tieneDobleFactor := validarLogin(posicionUser, user.Password[0])
		if loginOK {
			if tieneDobleFactor {
				codigoRandom := strings.ToUpper(randomString(5))
				hash := hashSHA512([]byte(codigoRandom))
				codigoHashed := hex.EncodeToString(hash[:])
				guardarCodFactor(codigoHashed, posicionUser)
				go func() { //en una subrutina para que el servidor responda rápido
					sendEmail(codigoRandom, users.Users[posicionUser].Email)
				}()
				response(w, true, "Doble factor")
				log.Println("Usuario: " + user.Login[0] + " --> Login correcto")
			} else {
				token := createJWTUser(user.Login[0])
				w.Header().Add("Token", token)
				guardarToken(token, posicionUser)
				response(w, true, token)
			}
		} else {
			response(w, false, "Error al loguear")
			log.Println("Usuario: " + user.Login[0] + " --> Login incorrecto")
		}
	} else {
		response(w, false, "Error al loguear")
		log.Println("Usuario: " + user.Login[0] + " --> Login incorrecto")
	}
}

// Función que valida si un login-password es correcto
//
// Recibe dos parámetros (login, password) y devuelve si
// es correcto el login y si tiene activado el doble factor
func validarLogin(posicionUser int, password string) (bool, bool) {
	if posicionUser >= 0 {
		if encriptarScrypt(password, users.Users[posicionUser].Salt) == users.Users[posicionUser].Password {
			return true, users.Users[posicionUser].FactorEnabled
		}
	}
	return false, false
}

// Función que le asigna un token a un usuario
//
// Recibe dos parámetros (token, user) y devuelve si
// se ha guardado correctamente
func guardarToken(token string, posicionUser int) bool {
	if posicionUser >= 0 {
		users.Users[posicionUser].Token = token
		return true
	}
	return false
}

// Función que le asigna un código de doble factor de
// autenticación a un usuario con expiración de 2 min.
//
// Recibe dos parámetros (codFactor, user) y devuelve si
// se ha guardado correctamente
func guardarCodFactor(codFactor string, posicionUser int) bool {
	if posicionUser >= 0 {
		users.Users[posicionUser].FactorCode = codFactor
		users.Users[posicionUser].FactorExp = strconv.Itoa(int(time.Now().Add(time.Minute * 2).Unix()))
		return true
	}
	return false
}

// Función handler llamada cuando un usuario
// realiza una petición de registro.
func handlerRegister(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()                                // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	body := buf.Bytes()

	type RegisterJSON struct {
		Register []string `json:"register"`
		Email    []string `json:"email"`
		Password []string `json:"password"`
		Confirm  []string `json:"confirm"`
	}
	var user RegisterJSON
	err := json.Unmarshal(body, &user)
	check(err)

	if err == nil {
		registrado, mensaje := validarRegister(user.Register[0], user.Email[0], user.Password[0], user.Confirm[0])
		response(w, registrado, mensaje)
	} else {
		response(w, false, "Error al registrar")
	}
}

func validarRegister(register string, email string, password string, confirm string) (bool, string) {
	if password != confirm || email == "" || register == "" || password == "" {
		return false, "Faltan datos por enviar"
	}
	existeUsuario, existeEmail := comprobarExisteUsuarioEmail(register, email)

	if existeUsuario {
		log.Println("Usuario: " + register + " --> Register incorrecto, ya existe el usuario")
		return false, "Ese usuario ya existe"
	}
	if existeEmail {
		log.Println("Usuario: " + register + " --> Register incorrecto, ya existe el email")
		return false, "Ese email ya existe"
	}

	salt := randomString(32)
	cifrado := randomString(32)

	users.Users = append(users.Users, User{User: register, Email: email, Password: encriptarScrypt(password, salt),
		Salt: salt, Cifrado: cifrado, FactorEnabled: false})

	log.Println("Usuario: " + register + " --> Register correcto")
	return true, "Registrado correctamente"
}

func comprobarExisteUsuarioEmail(usuario string, email string) (bool, bool) {
	existeUsuario := false
	existeEmail := false

	for i := 0; i < len(users.Users); i++ {
		if usuario == users.Users[i].User {
			existeUsuario = true
		}
		if email == users.Users[i].Email {
			existeEmail = true
		}
	}
	return existeUsuario, existeEmail
}

func handlerDobleFactor(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()                                // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	body := buf.Bytes()

	type BodyJSON struct {
		User     []string `json:"user"`
		Password []string `json:"password"`
		Codigo   []string `json:"codigo"`
	}
	var bodyJSON BodyJSON
	err := json.Unmarshal(body, &bodyJSON)
	check(err)

	posicionUser := getUser(bodyJSON.User[0])
	if posicionUser >= 0 {
		codigoValido, msg := validarCodigo(bodyJSON.Codigo[0], posicionUser, bodyJSON.Password[0])
		if err == nil && codigoValido {
			token := createJWTUser(bodyJSON.User[0])
			w.Header().Add("Token", token)
			guardarToken(token, posicionUser)
			log.Println("Usuario: " + bodyJSON.User[0] + " --> Doble factor de autenticación correcto")
			response(w, true, msg)
		} else {
			log.Println("Usuario: " + bodyJSON.User[0] + " --> Doble factor de autenticación incorrecto")
			response(w, false, msg)
		}
	} else {
		log.Println("Usuario: " + bodyJSON.User[0] + " --> Doble factor de autenticación incorrecto")
		response(w, false, "Doble factor de autenticación incorrecto")
	}
}

func validarCodigo(codigo string, posicionUser int, pass string) (bool, string) {
	loginOK, tieneDobleFactor := validarLogin(posicionUser, pass)
	if !loginOK {
		return false, "Credenciales no válidas"
	}
	if !tieneDobleFactor {
		return false, "Este usuario no tiene doble factor"
	}
	if codigo == "" || posicionUser < 0 {
		return false, "Malas credenciales"
	}
	if codigo == users.Users[posicionUser].FactorCode {
		tiempoFactor, err := strconv.ParseFloat(users.Users[posicionUser].FactorExp, 64)
		check(err)
		if tiempoFactor < float64(time.Now().Unix()) {
			return false, "El código ha expirado"
		}
		return true, "Código válido"
	}
	return false, "Código inválido"
}

func handlerHash(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()                                // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	body := buf.Bytes()

	type BodyJSON struct {
		Cont     []string `json:"cont"`
		Hash     []string `json:"hash"`
		Size     []string `json:"size"`
		User     []string `json:"user"`
		Filename []string `json:"filename"`
	}
	var bodyJSON BodyJSON
	err := json.Unmarshal(body, &bodyJSON)
	check(err)

	if err == nil {
		contador, _ := strconv.Atoi(bodyJSON.Cont[0])  // numero del orden de la parte del fichero
		hash := bodyJSON.Hash[0]                       // hash de la parte del fichero
		size, _ := strconv.Atoi(bodyJSON.Size[0])      // tamaño de la parte del fichero
		user := bodyJSON.User[0]                       // usuario que sube el fichero
		filename := decodeURLB64(bodyJSON.Filename[0]) // nombre del fichero original

		comprobar := comprobarHash(contador, hash, size, user, filename)
		response(w, comprobar, "Hash comprobado")
	} else {
		response(w, false, "Error al comprobar")
	}
}

func comprobarHash(cont int, hash string, tam int, user string, filename string) bool {
	existeBloque, nombreBloque := existeBloqueHash(hash)

	if existeBloque {
		var position BlockPosition
		parte := strconv.Itoa(cont)
		position.Block = nombreBloque
		position.Position = parte
		position.Size = strconv.Itoa(tam)
		registrarFileUsuario(user, filename, position)
		return true
	}
	return false
}

func existeBloqueHash(hash string) (bool, string) {
	for i := 0; i < len(blocks.Blocks); i++ {
		if hash == blocks.Blocks[i].Hash {
			return true, blocks.Blocks[i].Block
		}
	}
	return false, "nil"
}

func handlerUpload(w http.ResponseWriter, r *http.Request) {
	//todo cifrar el file, y guardarlo
	r.ParseMultipartForm(32 << 20)
	posicionUser := getUser(r.FormValue("Username"))
	if posicionUser >= 0 {
		file, handler, err := r.FormFile("uploadfile")
		check(err)
		defer file.Close()
		fileBytes, _ := ioutil.ReadAll(file)

		last := getNombreUltimoFichero()
		value, err := strconv.Atoi(last)
		value++
		path := strconv.Itoa(value)

		f, err := os.OpenFile(rutaArchivos+path, os.O_WRONLY|os.O_CREATE, 0766)
		check(err)
		defer f.Close()
		clave := users.Users[posicionUser].Cifrado
		encryptedFile := encryptAESCFB(fileBytes, clave)
		io.Copy(f, bytes.NewReader(encryptedFile))

		var position BlockPosition
		position.Block = path
		position.Position = r.FormValue("Parte")
		position.Size = r.FormValue("Size")

		var block Block
		block.User = r.FormValue("Username")
		block.Hash = r.FormValue("Hash")
		block.Block = path
		blocks.Blocks = append(blocks.Blocks, Block{Block: block.Block, Hash: block.Hash, User: block.User}) //lo guarda en Blocks
		registrarFileUsuario(r.FormValue("Username"), decodeURLB64(handler.Filename), position)              //lo guarda en Files
		comprobarBloquesSueltos()
	}
}

func registrarFileUsuario(usuario string, fichero string, bloque BlockPosition) {
	existe, bloquesDeArchivo, count := existeFicheroUsuario(usuario, fichero)

	if !existe { // Primer bloque de un nuevo archivo
		bloquesDeArchivo = append(bloquesDeArchivo, bloque)
		files.Files = append(files.Files, File{User: usuario, File: fichero, Order: bloquesDeArchivo})
	} else {
		// Si ya existe un usuario-file, comprueba que el bloque-posicion existe, si no existe, lo crea, sino lo sobrescribe
		asignado := false
		var nuevosBloquesDeArchivo []BlockPosition
		for i := 0; i < len(bloquesDeArchivo); i++ {
			if bloque.Position == bloquesDeArchivo[i].Position {
				bloquesDeArchivo[i] = bloque
				asignado = true
			}
			nuevosBloquesDeArchivo = append(nuevosBloquesDeArchivo, bloquesDeArchivo[i])
		}
		if asignado {
			bloquesDeArchivo = nuevosBloquesDeArchivo
		} else {
			bloquesDeArchivo = append(bloquesDeArchivo, bloque)
		}

		posicionBloque, err := strconv.Atoi(bloque.Position)
		check(err)
		if posicionBloque+1 < len(bloquesDeArchivo) {
			eliminarBloquesUsuario(bloquesDeArchivo[posicionBloque+1:], usuario)

			bloquesDeArchivo = bloquesDeArchivo[:posicionBloque+1]
		}
		files.Files[count].Order = bloquesDeArchivo
	}
}

func existeFicheroUsuario(usuario string, fichero string) (bool, []BlockPosition, int) {
	for i := 0; i < len(files.Files); i++ {
		if usuario == files.Files[i].User && fichero == files.Files[i].File {
			return true, files.Files[i].Order, i
		}
	}
	return false, nil, 0
}

func handlerShowUserFiles(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	check(err)
	result := strings.Split(u.Path, "/")
	username := result[len(result)-2]

	type FilesJSON struct {
		Filename []string `json:"filename"`
		Size     []string `json:"size"`
	}

	filesUser, tamFiles := getFilesUser(username)
	var filesJSON = FilesJSON{Filename: filesUser, Size: tamFiles}

	if len(filesUser) > 0 {
		slc, _ := json.Marshal(filesJSON)
		w.Write(slc)
	} else {
		response(w, false, "No tienes ficheros subidos")
	}
}

func getFilesUser(username string) ([]string, []string) {
	var filesUser []string
	var tamFiles []string
	for i := 0; i < len(files.Files); i++ {
		if username == files.Files[i].User {
			filesUser = append(filesUser, encodeURLB64(files.Files[i].File))
			tamanyo := 0
			for j := range files.Files[i].Order {
				x, _ := strconv.Atoi(files.Files[i].Order[j].Size)
				tamanyo += x
			}
			total := strconv.Itoa(tamanyo)
			tamFiles = append(tamFiles, total)
		}
	}
	return filesUser, tamFiles
}

func handlerDeleteFile(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	check(err)
	result := strings.Split(u.Path, "/")
	userSolicitante := result[len(result)-3]
	archivoSolicitado := decodeURLB64(result[len(result)-1])

	existe := false
	var bloquesDeArchivo []BlockPosition
	for i := 0; i < len(files.Files) && !existe; i++ {
		if files.Files[i].User == userSolicitante && files.Files[i].File == archivoSolicitado {
			existe = true
			bloquesDeArchivo = files.Files[i].Order
		}
	}

	if !existe {
		response(w, false, "El usuario no dispone de este archivo")
	} else {
		eliminarBloquesUsuario(bloquesDeArchivo, userSolicitante)
		eliminarArchivoUsuario(userSolicitante, archivoSolicitado)
		response(w, true, "Borrado")
	}
}

func asignarNuevaClave(path string, claveOriginal string, claveNueva string) {
	file, err := ioutil.ReadFile(path)
	check(err)

	if len(file) > 0 {
		decryptedFile := decryptAESCFB(file, claveOriginal)
		deleteFile(path)

		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
		check(err)
		defer f.Close()

		encryptedFile := encryptAESCFB(decryptedFile, claveNueva)
		io.Copy(f, bytes.NewReader(encryptedFile))
	}
}

func getPosicionBloque(bloque string) (int, error) {
	for i := 0; i < len(blocks.Blocks); i++ {
		if blocks.Blocks[i].Block == bloque {
			return i, nil
		}
	}
	return -1, errors.New("Ese bloque no existe")
}

func eliminarBloquesUsuario(bloquesDeArchivo []BlockPosition, userSolicitante string) {
	for i := 0; i < len(bloquesDeArchivo); i++ {
		var bloqueCambiado = false
		for j := 0; j < len(files.Files); j++ {
			for k := 0; k < len(files.Files[j].Order) && !bloqueCambiado; k++ {
				if bloquesDeArchivo[i].Block == files.Files[j].Order[k].Block {
					otroUsuarioBloque, otroUsuarioTiene := checkUsersBlocks(userSolicitante, bloquesDeArchivo[i].Block)
					if !otroUsuarioTiene {
						if !isBlockUsed(userSolicitante, bloquesDeArchivo[i].Block) {
							deleteFile(rutaArchivos + bloquesDeArchivo[i].Block)
							eliminarBloque(bloquesDeArchivo[i].Block)
						}
					} else {
						claveOriginal, nuevaClave, err := obtenerClavesUsuarios(bloquesDeArchivo[i].Block, otroUsuarioBloque)
						check(err)

						asignarNuevaClave(rutaArchivos+bloquesDeArchivo[i].Block, claveOriginal, nuevaClave)

						posicion, err := getPosicionBloque(bloquesDeArchivo[i].Block)
						if err == nil {
							blocks.Blocks[posicion].User = otroUsuarioBloque
						} else {
							check(err)
						}
					}
					bloqueCambiado = true
				}
			}
		}
	}
}

func comprobarBloquesSueltos() {
	for i := 0; i < len(blocks.Blocks); i++ {
		asignado := false
		for j := 0; j < len(files.Files) && !asignado; j++ {
			for k := 0; k < len(files.Files[j].Order) && !asignado; k++ {
				if blocks.Blocks[i].Block == files.Files[j].Order[k].Block {
					asignado = true
				}
			}
		}
		if !asignado {
			deleteFile(rutaArchivos + blocks.Blocks[i].Block)
			eliminarBloque(blocks.Blocks[i].Block)
		}
	}
}

func eliminarArchivoUsuario(usuario string, archivo string) bool {
	borrado := false
	for i := 0; i < len(files.Files) && !borrado; i++ {
		if files.Files[i].File == archivo && files.Files[i].User == usuario {
			files.Files = append(files.Files[:i], files.Files[i+1:]...)
			borrado = true
		}
	}
	return borrado
}

func eliminarBloque(bloque string) bool {
	borrado := false
	for i := 0; i < len(blocks.Blocks) && !borrado; i++ {
		if blocks.Blocks[i].Block == bloque {
			blocks.Blocks = append(blocks.Blocks[:i], blocks.Blocks[i+1:]...)
			borrado = true
		}
	}
	return borrado
}

func obtenerClavesUsuarios(bloque string, nuevoUsuario string) (string, string, error) {
	claveUsuarioOriginal := obtenerClaveCifrado(rutaArchivos + bloque)

	posicionUser := getUser(nuevoUsuario)
	if posicionUser >= 0 {
		claveNuevoUsuario := users.Users[posicionUser].Cifrado
		return claveUsuarioOriginal, claveNuevoUsuario, nil
	}

	return "", "", errors.New("Error al obtener las claves")
}

func checkUsersBlocks(username string, block string) (string, bool) {
	//comprueba si alquien a parte de ti tiene el bloque
	for i := 0; i < len(files.Files); i++ {
		for j := 0; j < len(files.Files[i].Order); j++ {
			if files.Files[i].Order[j].Block == block && files.Files[i].User != username {
				return files.Files[i].User, true
			}
		}
	}
	return "false", false
}

func isBlockUsed(username string, block string) bool {
	contador := 0
	for i := 0; i < len(files.Files); i++ {
		for j := 0; j < len(files.Files[i].Order); j++ {
			if files.Files[i].Order[j].Block == block && files.Files[i].User == username {
				contador++
			}
		}
	}
	if contador > 1 {
		return true
	}
	return false
}

func handlerSendFile(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	check(err)
	result := strings.Split(u.Path, "/")

	userSolicitante := result[len(result)-3]
	archivoSolicitado := decodeURLB64(result[len(result)-1])

	existe, bloquesDeArchivo, _ := existeFicheroUsuario(userSolicitante, archivoSolicitado)

	if !existe {
		response(w, false, "El archivo No Existe")
	} else {
		formatoArchivo := strings.Split(archivoSolicitado, ".")
		var bytesTotal []byte
		for i := 0; i < len(bloquesDeArchivo); i++ {
			ruta := rutaArchivos + bloquesDeArchivo[i].Block
			leerBytes, err := ioutil.ReadFile(ruta)
			check(err)
			bytesDescifrados := decryptAESCFB(leerBytes, obtenerClaveCifrado(ruta))
			bytesTotal = append(bytesTotal[:], bytesDescifrados[:]...)
		}
		kind := mime.TypeByExtension("." + formatoArchivo[len(formatoArchivo)-1])

		b := bytes.NewBuffer(bytesTotal)
		w.Header().Set("Content-type", kind)

		if _, err := b.WriteTo(w); err != nil {
			fmt.Fprintf(w, "%s", err)
		}
	}
}

func getNombreUltimoFichero() string {
	final := "-1"
	for i := 0; i < len(blocks.Blocks); i++ {
		final = blocks.Blocks[i].Block
	}
	return final
}

func cifrarCarpeta(ruta string) {
	err := filepath.Walk(ruta, visitEncrypt) //esta funcion recorre todos los directorios y ficheros recursivamente
	check(err)
}

func visitEncrypt(path string, f os.FileInfo, err error) error {
	if f != nil && f.IsDir() == false { //para coger solo los ficheros y no las carpetas
		clavemaestra, err := getMasterKey(rutaMasterKey)
		check(err)
		cifrarFichero(path, clavemaestra)
	}
	return nil
}

func cifrarFichero(path string, clave string) {
	file, err := ioutil.ReadFile(path)
	check(err)

	if len(file) > 0 {
		encryptedFile := encryptAESCFB(file, clave)
		deleteFile(path)

		filenew, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
		check(err)
		defer filenew.Close()
		io.Copy(filenew, bytes.NewReader(encryptedFile))
	}
}

func descifrarCarpeta(ruta string) {
	//recorrer todos los ficheros y cifrarlos con una contraseña maestra
	err := filepath.Walk(ruta, visitDecrypt) //esta funcion recorre todos los directorios y ficheros recursivamente
	check(err)
}

func visitDecrypt(path string, f os.FileInfo, err error) error {
	if f != nil && f.IsDir() == false { //para coger solo los ficheros y no las carpetas
		clavemaestra, err := getMasterKey(rutaMasterKey)
		check(err)
		descifrarFichero(path, clavemaestra)
	}
	return nil
}

func descifrarFichero(path string, clave string) {
	file, err := ioutil.ReadFile(path)
	check(err)

	if len(file) > 0 {
		encryptedFile := decryptAESCFB(file, clave)
		deleteFile(path)

		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
		check(err)
		defer f.Close()
		io.Copy(f, bytes.NewReader(encryptedFile))
	}
}

func obtenerClaveCifrado(path string) string {
	nombreBloque := strings.Split(path, "/")
	bloque := nombreBloque[len(nombreBloque)-1]

	var userPropietarioClave string
	var encontrado = false
	for i := 0; i < len(blocks.Blocks) && !encontrado; i++ {
		if bloque == blocks.Blocks[i].Block {
			userPropietarioClave = blocks.Blocks[i].User
			encontrado = true
		}
	}

	posicionUser := getUser(userPropietarioClave)
	if posicionUser >= 0 {
		return users.Users[posicionUser].Cifrado
	}
	return ""
}

func handlerSendAjustes(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	check(err)
	result := strings.Split(u.Path, "/")
	username := result[len(result)-2]

	type AjustesJSON struct {
		Email       string `json:"size"`
		Doblefactor bool   `json:"doblefactor"`
	}

	existe, email, dobleFactor := getAjustes(username)

	if existe {
		var ajustesJSON = AjustesJSON{Email: email, Doblefactor: dobleFactor}
		slc, _ := json.Marshal(ajustesJSON)
		w.Write(slc)
	} else {
		response(w, false, "Ajustes no encontrados")
	}
}

func getAjustes(user string) (bool, string, bool) {
	posicionUser := getUser(user)
	if posicionUser >= 0 {
		return true, users.Users[posicionUser].Email, users.Users[posicionUser].FactorEnabled
	}
	return false, "", false
}

func handlerEditAjustes(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()                                // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	body := buf.Bytes()

	type AjustesJSON struct {
		User        []string `json:"user"`
		Email       []string `json:"email"`
		DobleFactor []string `json:"doblefactor"`
	}
	var ajustes AjustesJSON
	err := json.Unmarshal(body, &ajustes)
	check(err)

	dobleFactor, err := strconv.ParseBool(ajustes.DobleFactor[0])
	check(err)
	editado := editAjustes(ajustes.User[0], ajustes.Email[0], dobleFactor)

	if editado {
		response(w, true, "Ajustes editados correctamente")
	} else {
		response(w, false, "Los ajustes no han sido editados")
	}
}

func editAjustes(user string, email string, dobleFactor bool) bool {
	posicionUser := getUser(user)
	if posicionUser >= 0 {
		users.Users[posicionUser].Email = email
		users.Users[posicionUser].FactorEnabled = dobleFactor
		return true
	}
	return false
}

func handlerShowInfo(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	check(err)
	result := strings.Split(u.Path, "/")
	username := result[len(result)-2]

	filesUser, tamFiles := getFilesUser(username)
	archivosTotal := strconv.Itoa(len(filesUser))
	tamTotal := 0
	for i := range tamFiles {
		tam, err := strconv.Atoi(tamFiles[i])
		check(err)
		tamTotal += tam
	}
	totalTam := strconv.Itoa(tamTotal)

	type InfoJSON struct {
		Files     string `json:"files"`
		TotalSize string `json:"totalsize"`
	}
	var infoJSON = InfoJSON{Files: archivosTotal, TotalSize: totalTam}
	slc, _ := json.Marshal(infoJSON)
	w.Write(slc)
}

func middlewareAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValido := validarTokenUser(r.Header.Get("Authorization"), r.Header.Get("Username"))
		if tokenValido {
			next.ServeHTTP(w, r)
		} else {
			response(w, false, "Error de autenticación")
		}
	})
}

func main() {
	contraseñamaestra, err := getMasterKey(rutaMasterKey)
	if err == nil && contraseñamaestra != "" {
		fmt.Println("Iniciando servidor...")
		rand.Seed(time.Now().UTC().UnixNano()) //para que el aleatorio funcione bien
		createDirIfNotExist(rutaArchivos)
		createDirIfNotExist(rutaCertificados)
		createDirIfNotExist(rutaDatabases)

		//Archivo log
		f, err := os.OpenFile(rutaLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Error abriendo el fichero: %v", err)
			fmt.Printf("Error abriendo el fichero: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)

		stopChan := make(chan os.Signal)
		signal.Notify(stopChan, os.Interrupt)

		// Comprueba los certificados, si no existen se generan nuevos
		err = httpscerts.Check(rutaCertificados+"/cert.pem", rutaCertificados+"/key.pem")
		if err != nil {
			err = httpscerts.Generate(rutaCertificados+"/cert.pem", rutaCertificados+"/key.pem", ":8081")
			cifrarCarpeta(rutaCertificados)
			if err != nil {
				log.Fatal("Error: No se han podido crear los certificados https.")
				fmt.Println("Error: No se han podido crear los certificados https.")
			}
		}

		muxa := mux.NewRouter()
		muxa.HandleFunc("/", handler)
		muxa.HandleFunc("/login", handlerLogin)
		muxa.HandleFunc("/register", handlerRegister)
		muxa.HandleFunc("/doblefactor", handlerDobleFactor)
		muxa.Handle("/checkhash", middlewareAuth(http.HandlerFunc(handlerHash)))
		muxa.Handle("/upload", middlewareAuth(http.HandlerFunc(handlerUpload)))
		muxa.Handle("/user/{username}/files", middlewareAuth(http.HandlerFunc(handlerShowUserFiles)))
		muxa.Handle("/user/{username}/file/{filename}", middlewareAuth(http.HandlerFunc(handlerSendFile))).Methods("GET")
		muxa.Handle("/user/{username}/file/{filename}", middlewareAuth(http.HandlerFunc(handlerDeleteFile))).Methods("DELETE")
		muxa.Handle("/user/{username}/ajustes", middlewareAuth(http.HandlerFunc(handlerSendAjustes))).Methods("GET")
		muxa.Handle("/user/{username}/ajustes", middlewareAuth(http.HandlerFunc(handlerEditAjustes))).Methods("POST")
		muxa.Handle("/user/{username}/info", middlewareAuth(http.HandlerFunc(handlerShowInfo)))

		srv := &http.Server{Addr: ":8081", Handler: muxa}

		log.Println("Descifrando y leyendo bases de datos...")
		archivo := leerArchivo(rutaUsersBD)
		if len(archivo) == 0 {
			escribirArchivo(rutaUsersBD, encryptAESCFB([]byte(`{"users":[]}`), contraseñamaestra))
			archivo = leerArchivo(rutaUsersBD)
		}
		bytesDescifrados := decryptAESCFB(archivo, contraseñamaestra)
		err = json.Unmarshal(bytesDescifrados, &users)
		check(err)

		archivo = leerArchivo(rutaFilesBD)
		if len(archivo) == 0 {
			escribirArchivo(rutaFilesBD, encryptAESCFB([]byte(`{"files":[]}`), contraseñamaestra))
			archivo = leerArchivo(rutaFilesBD)
		}
		bytesDescifrados = decryptAESCFB(archivo, contraseñamaestra)
		err = json.Unmarshal(bytesDescifrados, &files)
		check(err)

		archivo = leerArchivo(rutaBlocksBD)
		if len(archivo) == 0 {
			escribirArchivo(rutaBlocksBD, encryptAESCFB([]byte(`{"blocks":[]}`), contraseñamaestra))
			archivo = leerArchivo(rutaBlocksBD)
		}
		bytesDescifrados = decryptAESCFB(archivo, contraseñamaestra)
		err = json.Unmarshal(bytesDescifrados, &blocks)
		check(err)

		log.Println("Descifrando certificados HTTPS...")
		descifrarCarpeta(rutaCertificados)

		go func() {
			log.Println("Poniendo en marcha servidor HTTPS, escuchando puerto 8081")
			fmt.Println("Poniendo en marcha servidor HTTPS, escuchando puerto 8081")
			if err := srv.ListenAndServeTLS(rutaCertificados+"/cert.pem", rutaCertificados+"/key.pem"); err != nil {
				log.Printf("Error al poner en funcionamiento el servidor TLS: %s\n", err)
				fmt.Printf("Error al poner en funcionamiento el servidor TLS: %s\n", err)
			}
		}()
		go func() {
			log.Println("Poniendo en marcha redireccionamiento HTTP->HTTPS, escuchando puerto 8080")
			fmt.Println("Poniendo en marcha redireccionamiento HTTP->HTTPS, escuchando puerto 8080")
			if err := http.ListenAndServe(":8080", http.HandlerFunc(redirectToHTTPS)); err != nil {
				log.Printf("Error al redireccionar HTTP a HTTPS: %s\n", err)
				fmt.Printf("Error al redireccionar HTTP a HTTPS: %s\n", err)
			}
		}()

		<-stopChan // espera señal SIGINT
		log.Println("Apagando servidor ...")
		// apagar servidor de forma segura
		ctx, fnc := context.WithTimeout(context.Background(), 5*time.Second)
		fnc()
		srv.Shutdown(ctx)

		log.Println("Cifrando y guardando bases de datos...")
		usersJSON, _ := json.Marshal(&users)
		escribirArchivo(rutaUsersBD, encryptAESCFB(usersJSON, contraseñamaestra))

		filesJSON, _ := json.Marshal(&files)
		escribirArchivo(rutaFilesBD, encryptAESCFB(filesJSON, contraseñamaestra))

		blocksJSON, _ := json.Marshal(&blocks)
		escribirArchivo(rutaBlocksBD, encryptAESCFB(blocksJSON, contraseñamaestra))

		log.Println("Cifrando certificados https...")
		cifrarCarpeta(rutaCertificados)

		log.Println("Servidor detenido correctamente")
		fmt.Println("Servidor detenido correctamente")
	} else {
		fmt.Println("El servidor necesita una master.key para iniciar")
	}
}
