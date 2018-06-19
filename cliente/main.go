package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/dtylman/gowd"
	"github.com/dtylman/gowd/bootstrap"
)

var body *gowd.Element
var mostrar = "login"
var login = ""
var token = ""
var password = ""

type resp struct {
	Ok  bool   `json:"ok"`  // true -> correcto, false -> error
	Msg string `json:"msg"` // mensaje adicional
}

func main() {
	body = bootstrap.NewElement("div", "wrapper")
	body.AddHTML(`<button id="restart" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
	logo := `<div style="margin:0 auto;width:30%;"><img src="assets/img/logo_alargado.png" style="width:100%;margin:0 auto"/></div>`

	switch mostrar {
	case "login":
		body.SetAttribute("style", "background-color:#FF654E; height: 100%")
		body.AddHTML(logo, nil)
		body.AddHTML(vistaLogin(), nil)
		body.Find("login-submit").OnEvent(gowd.OnClick, sendLogin)
		body.Find("register-form-link").OnEvent(gowd.OnClick, goRegister)
		body.Find("login-form-link").OnEvent(gowd.OnClick, goLogin)
		element := body.Find("restart")
		if element != nil {
			element.OnEvent(gowd.OnClick, goLogin)
		}
		break
	case "register":
		body.SetAttribute("style", "background-color:#FF654E; height: 100%")
		body.AddHTML(logo, nil)
		body.AddHTML(vistaRegister(), nil)
		body.Find("register-submit").OnEvent(gowd.OnClick, sendRegister)
		body.Find("register-form-link").OnEvent(gowd.OnClick, goRegister)
		body.Find("login-form-link").OnEvent(gowd.OnClick, goLogin)
		element := body.Find("restart")
		if element != nil {
			element.OnEvent(gowd.OnClick, goRegister)
		}
		break
	case "principal":
		body.SetAttribute("style", "background-color:#ecf0f5; height: 100%")
		body.AddHTML(vistaPrincipal(), nil)
		body.Find("recargar").OnEvent(gowd.OnClick, goPrincipal)
		body.Find("buttonEnviar").OnEvent(gowd.OnClick, seleccionarFichero)
		body.Find("logout-link").OnEvent(gowd.OnClick, goLogin)
		body.Find("buttonPedir").OnEvent(gowd.OnClick, pedirFichero)
		body.Find("buttonEliminar").OnEvent(gowd.OnClick, eliminarFichero)
		body.Find("ajustes").OnEvent(gowd.OnClick, goAjustes)
		element := body.Find("restart")
		if element != nil {
			element.OnEvent(gowd.OnClick, goPrincipal)
		}
		break
	case "doblefactor":
		body.SetAttribute("style", "background-color:#FF654E; height: 100%")
		body.AddHTML(logo, nil)
		body.AddHTML(vistaFactor(), nil)
		body.Find("login-submit").OnEvent(gowd.OnClick, sendDobleFactor)
		body.Find("register-form-link").OnEvent(gowd.OnClick, goRegister)
		body.Find("login-form-link").OnEvent(gowd.OnClick, goLogin)
		element := body.Find("restart")
		if element != nil {
			element.OnEvent(gowd.OnClick, goLogin)
		}
		break
	case "ajustes":
		body.SetAttribute("style", "background-color:#ecf0f5; height: 100%")
		body.AddHTML(vistaAjustes(), nil)
		body.Find("ajustes-submit").OnEvent(gowd.OnClick, sendAjustes)
		body.Find("recargar").OnEvent(gowd.OnClick, goPrincipal)
		body.Find("logout-link").OnEvent(gowd.OnClick, goLogin)
		body.Find("ajustes").OnEvent(gowd.OnClick, goAjustes)
		element := body.Find("restart")
		if element != nil {
			element.OnEvent(gowd.OnClick, goAjustes)
		}
		actualizarAjustes()
		break
	}
	//start the ui loop
	err := gowd.Run(body)
	check(err)
}

func sendLogin(sender *gowd.Element, event *gowd.EventElement) {
	usuario := body.Find("usuario").GetValue()
	pass := body.Find("contraseña").GetValue()

	if usuario != "" && pass != "" {
		data := url.Values{} // estructura para contener los valores
		data.Set("login", usuario)
		pashHashed := string(hashSHA512([]byte(pass)))
		data.Set("password", pashHashed)

		bytesJSON, err := json.Marshal(data)
		check(err)
		reader := bytes.NewReader(bytesJSON)

		response := sendServerPetition("POST", reader, "/login", "application/json")
		defer response.Body.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)

		var respuesta resp
		err = json.Unmarshal(buf.Bytes(), &respuesta)
		check(err)

		if err == nil && respuesta.Ok == true {
			if respuesta.Msg == "Doble factor" {
				login = usuario
				password = pashHashed
				goDobleFactor(nil, nil)
			} else {
				login = usuario
				token = response.Header.Get("Token")
				goPrincipal(nil, nil)
			}
		} else if err == nil {
			modalError("Error desconocido", "Ha ocurrido un problema con el servidor.<p>"+respuesta.Msg+"</p>")
		} else {
			modalError("Error desconocido", "Ha ocurrido un problema con el servidor.")
		}
	} else {
		modalError("Error", "Faltan datos por rellenar")
	}
}

func sendRegister(sender *gowd.Element, event *gowd.EventElement) {
	usuario := body.Find("registerUser").GetValue()
	email := body.Find("registerEmail").GetValue()
	pass := body.Find("registerPassword").GetValue()
	confirm := body.Find("confirmPassword").GetValue()

	if usuario != "" && email != "" && pass != "" && confirm != "" {
		if pass == confirm {
			data := url.Values{} // estructura para contener los valores
			data.Set("register", usuario)
			data.Set("email", email)
			data.Set("password", string(hashSHA512([]byte(pass))))
			data.Set("confirm", string(hashSHA512([]byte(confirm))))

			bytesJSON, err := json.Marshal(data)
			check(err)
			reader := bytes.NewReader(bytesJSON)

			response := sendServerPetition("POST", reader, "/register", "application/json")
			defer response.Body.Close()

			buf := new(bytes.Buffer)
			buf.ReadFrom(response.Body)

			var respuesta resp
			err = json.Unmarshal(buf.Bytes(), &respuesta)
			check(err)

			if err == nil && respuesta.Ok == true {
				modalNormal("Registrado correctamente", "El usuario '"+usuario+"' ha sido registrado correctamente.")
			} else if err == nil {
				modalError("Problema al registrar", "Ha ocurrido un problema al registrar: <p>"+respuesta.Msg+"</p>")
			} else {
				modalError("Error desconocido", "Ha ocurrido un problema con el servidor.")
			}
		} else {
			modalError("Error", "Las contraseñas no coinciden")
		}
	} else {
		modalError("Error", "Faltan datos por rellenar")
	}
}

func seleccionarFichero(sender *gowd.Element, event *gowd.EventElement) {
	//fmt.Println(body.Find("archivo").GetValue())
	ruta := body.Find("route").GetValue()
	filename := body.Find("filename").GetValue()
	enviarFichero(ruta, encodeURLB64(filename))
}

func enviarFichero(ruta string, filename string) {
	f, err := os.Open(ruta)
	check(err)
	defer f.Close()
	bytesTam := 1024 * 1024 * 4 //byte -> kb -> mb * 4
	bytes := make([]byte, bytesTam)
	bytesLeidos, err := f.Read(bytes)
	check(err)

	if bytesLeidos > 0 && bytesLeidos < bytesTam { //si solo hay una parte
		bytes = bytes[:bytesLeidos] // para que no ocupe 4mb siempre
	}

	contador := 0
	contadorBytes := bytesLeidos
	texto := strconv.Itoa(contador) + ": " + strconv.Itoa(bytesLeidos) + ", "
	enviarParteFichero(contador, bytes, bytesLeidos, filename)

	for bytesLeidos > 0 {
		bytesLeidos, err = f.ReadAt(bytes, int64(contadorBytes))
		check(err)
		contador++
		contadorBytes += bytesLeidos
		if bytesLeidos > 0 {
			if bytesLeidos < bytesTam { //ultima parte
				bytes = bytes[:bytesLeidos] // para que no ocupe 4mb siempre
			}
			texto += strconv.Itoa(contador) + ": " + strconv.Itoa(bytesLeidos) + ", "
			enviarParteFichero(contador, bytes, bytesLeidos, filename)
		}
	}
	modalNormal("Fichero subido correctamente", "El fichero ha sido enviado correctamente.")
}

func enviarParteFichero(cont int, parte []byte, tam int, filename string) {
	//preparar peticion
	data := url.Values{} // estructura para contener los valores
	contador := strconv.Itoa(cont)
	hash := hashSHA512(parte)
	size := strconv.Itoa(tam)
	data.Set("cont", contador)
	data.Set("hash", hex.EncodeToString(hash))
	data.Set("size", size)
	data.Set("user", login)
	data.Set("filename", filename)

	bytesJSON, err := json.Marshal(data)
	check(err)
	reader := bytes.NewReader(bytesJSON)

	//imprimir := "Pieza: " + contador + " hash: " + hex.EncodeToString(hash) + " size: " + size + " user: " + login + " filename: " + filename

	/**************************** conseguir usuario *************************/
	response := sendServerPetition("POST", reader, "/checkhash", "application/json")
	defer response.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)

	var respuesta resp
	err = json.Unmarshal(buf.Bytes(), &respuesta)
	check(err)

	if err != nil || (respuesta.Ok == false && respuesta.Msg != "Hash comprobado") {
		modalError("Error desconocido", "Ha ocurrido un problema con el servidor.<p>"+respuesta.Msg+"</p>")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
	} else if respuesta.Ok == false && respuesta.Msg == "Hash comprobado" { //el hash no existe en el servidor (la parte no se ha subido nunca)
		enviarDatos(parte, filename, contador, hex.EncodeToString(hash), size)
	}
}

func enviarDatos(data []byte, filename string, parte string, hash string, size string) {
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)
	err := bodyWriter.WriteField("Username", login)
	check(err)
	err = bodyWriter.WriteField("Parte", parte)
	check(err)
	err = bodyWriter.WriteField("Hash", hash)
	check(err)
	err = bodyWriter.WriteField("Size", size)
	check(err)

	// this step is very important
	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", filename)
	check(err)

	r := bytes.NewReader(data)
	_, err = io.Copy(fileWriter, r)
	check(err)

	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	sendServerPetition("POST", bodyBuf, "/upload", contentType)
}

func pedirFichero(sender *gowd.Element, event *gowd.EventElement) {
	fichero := body.Find("archivoPedido").GetValue()
	filename := encodeURLB64(fichero)
	response := sendServerPetition("GET", nil, "/user/"+login+"/file/"+filename, "application/json")
	defer response.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	var respuestaJSON resp
	err := json.Unmarshal(buf.Bytes(), &respuestaJSON)
	if err == nil && respuestaJSON.Ok == false && respuestaJSON.Msg != "" {
		modalError("Error desconocido", "Ha ocurrido un problema con el servidor.<p>"+respuestaJSON.Msg+"</p>")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
	} else {
		respuesta := buf.String()
		ex, err := os.Executable()
		if err != nil {
			panic(err)
		}
		exPath := filepath.Dir(ex)

		descargas := "." + string(os.PathSeparator) + "descargas" + string(os.PathSeparator)

		createDirIfNotExist(descargas + login)
		createFile(descargas + login + string(os.PathSeparator) + fichero)
		writeFile(descargas+login+string(os.PathSeparator)+fichero, respuesta)
		modalNormal("Fichero descargado", "El fichero '"+fichero+"' ha sido descargado correctamente en: <p>"+
			exPath+string(os.PathSeparator)+"descargas"+string(os.PathSeparator)+login+string(os.PathSeparator)+"</p>")
	}
}

func peticionNombreFicheros() string {
	response := sendServerPetition("GET", nil, "/user/"+login+"/files", "application/json")
	defer response.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	var respuestaJSON resp
	err := json.Unmarshal(buf.Bytes(), &respuestaJSON)
	respuesta := ""

	if err == nil && respuestaJSON.Ok == false && respuestaJSON.Msg != "" && respuestaJSON.Msg != "No tienes ficheros subidos" {
		modalError("Error desconocido", "Ha ocurrido un problema con el servidor.<p>"+respuestaJSON.Msg+"</p>")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
		return respuesta
	} else if err != nil {
		modalError("Error desconocido", "Ha ocurrido un problema con el servidor.")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
	}

	type FilesJSON struct {
		Filename []string `json:"filename"`
		Size     []string `json:"size"`
	}
	var filesJSON FilesJSON
	err = json.Unmarshal(buf.Bytes(), &filesJSON)
	if err == nil && len(filesJSON.Filename) != 0 && len(filesJSON.Size) != 0 && len(filesJSON.Filename) == len(filesJSON.Size) {
		for i := range filesJSON.Filename {
			tamanyo, _ := strconv.Atoi(filesJSON.Size[i])
			respuesta += `<tr>
				<td>
					<a href="#">` + decodeURLB64(filesJSON.Filename[i]) + `</a>
					<span style="float:right;">&nbsp;</span>
					<span style="float:right;">&nbsp;</span>
					<button type="button" class="btn btn-danger btn-xs" style="float: right;" onclick="eliminarArchivo('` + decodeURLB64(filesJSON.Filename[i]) + `')">
						<span class="glyphicon glyphicon-trash" aria-hidden="true"></span>
					</button>
					<span style="float:right;">&nbsp;</span>
					<span style="float:right;">&nbsp;</span>
					<button type="button" class="btn btn-primary btn-xs" style="float: right;" onclick="seleccionarArchivo('` + decodeURLB64(filesJSON.Filename[i]) + `')">
						<span class="glyphicon glyphicon-download-alt" aria-hidden="true"></span>
					</button>
					<span style="float:right;">&nbsp;</span>
					<span style="float:right;">&nbsp;</span>
				</td>
				<td>
					` + formatBytesToString(tamanyo) + `
				</td>
			</tr>`
		}
	}
	return respuesta
}

func eliminarFichero(sender *gowd.Element, event *gowd.EventElement) {
	filename := encodeURLB64(body.Find("archivoEliminar").GetValue())
	response := sendServerPetition("DELETE", nil, "/user/"+login+"/file/"+filename, "application/json")
	defer response.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	var respuestaJSON resp
	err := json.Unmarshal(buf.Bytes(), &respuestaJSON)
	if err == nil && respuestaJSON.Ok == false && respuestaJSON.Msg != "" {
		modalError("Error desconocido", "Ha ocurrido un problema con el servidor.<p>"+respuestaJSON.Msg+"</p>")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
	} else {
		modalNormal("Eliminando fichero", "Se ha eliminado el fichero '"+decodeURLB64(filename)+"' correctamente.")
	}
}

func sendDobleFactor(sender *gowd.Element, event *gowd.EventElement) {
	codigo := body.Find("codigo").GetValue()

	if codigo != "" {
		data := url.Values{} // estructura para contener los valores
		data.Set("user", login)
		data.Set("password", password)
		hash := hashSHA512([]byte(codigo))
		codigoHashed := hex.EncodeToString(hash)
		data.Set("codigo", codigoHashed)

		bytesJSON, err := json.Marshal(data)
		check(err)
		reader := bytes.NewReader(bytesJSON)

		response := sendServerPetition("POST", reader, "/doblefactor", "application/json")
		defer response.Body.Close()
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)

		var respuesta resp
		err = json.Unmarshal(buf.Bytes(), &respuesta)
		check(err)

		if err == nil && respuesta.Ok == true {
			token = response.Header.Get("Token")
			goPrincipal(nil, nil)
		} else if err != nil {
			modalError("Error desconocido", "Ha ocurrido un problema con el servidor.")
		} else {
			modalError("Error con el código", "Ha ocurrido un problema con el código.<p>"+respuesta.Msg+"</p>")
		}
	} else {
		modalError("Error", "Introduce algún código")
	}
}

func actualizarAjustes() {
	response := sendServerPetition("GET", nil, "/user/"+login+"/ajustes", "application/json")
	defer response.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	var respuestaJSON resp
	err := json.Unmarshal(buf.Bytes(), &respuestaJSON)

	if err == nil && respuestaJSON.Ok == false && respuestaJSON.Msg != "" {
		modalError("Error desconocido", "Ha ocurrido un problema con el servidor.<p>"+respuestaJSON.Msg+"</p>")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
	}

	type AjustesJSON struct {
		Email       string `json:"size"`
		Doblefactor bool   `json:"doblefactor"`
	}
	var ajustesJSON AjustesJSON
	err = json.Unmarshal(buf.Bytes(), &ajustesJSON)

	if err == nil {
		body.Find("email").SetAttribute("value", ajustesJSON.Email)
		if ajustesJSON.Doblefactor {
			body.Find("doblefactor").SetAttribute("checked", "checked")
		}
	}
}

func sendAjustes(sender *gowd.Element, event *gowd.EventElement) {
	email, _ := body.Find("email").GetAttribute("value")
	dobleFactor, _ := body.Find("doblefactor").GetAttribute("checked")
	if dobleFactor != "" {
		dobleFactor = "true"
	} else {
		dobleFactor = "false"
	}

	data := url.Values{} // estructura para contener los valores
	data.Set("user", login)
	data.Set("email", email)
	data.Set("doblefactor", dobleFactor)

	bytesJSON, err := json.Marshal(data)
	check(err)
	reader := bytes.NewReader(bytesJSON)

	response := sendServerPetition("POST", reader, "/user/"+login+"/ajustes", "application/json")
	defer response.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)

	var respuestaJSON resp
	err = json.Unmarshal(buf.Bytes(), &respuestaJSON)
	check(err)

	if err == nil && respuestaJSON.Ok == true {
		modalNormal("Ajustes editados", "Los ajustes han sido editados correctamente.")
	} else if err == nil && respuestaJSON.Msg != "" {
		//error al editar los ajustes
		modalError("Error al editar ajustes", "Ha ocurrido un problema con el servidor.<p>"+respuestaJSON.Msg+"</p>")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
	} else {
		modalError("Error desconocido", "Ha ocurrido un problema con el servidor.")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
	}
}

func getInfo() string {
	response := sendServerPetition("GET", nil, "/user/"+login+"/info", "application/json")
	defer response.Body.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(response.Body)
	var respuestaJSON resp
	err := json.Unmarshal(buf.Bytes(), &respuestaJSON)
	respuesta := ""

	if err == nil && respuestaJSON.Ok == false && respuestaJSON.Msg != "" {
		modalError("Error desconocido", "Ha ocurrido un problema con el servidor.<p>"+respuestaJSON.Msg+"</p>")
		element := body.Find("restart")
		if element != nil {
			body.RemoveElement(element)
		}
		body.AddHTML(`<button id="goLogin" type="button" class="btn btn-primary" style="display: none;"/>`, nil)
		body.Find("goLogin").OnEvent(gowd.OnClick, goLogin)
		return respuesta
	}

	type InfoJSON struct {
		Files     string `json:"files"`
		TotalSize string `json:"totalsize"`
	}
	var infoJSON InfoJSON
	err = json.Unmarshal(buf.Bytes(), &infoJSON)

	if err == nil && infoJSON.Files != "" && infoJSON.TotalSize != "" {
		totalBytes, err := strconv.Atoi(infoJSON.TotalSize)
		check(err)
		respuesta = `<span class="glyphicon glyphicon-duplicate"></span>&nbsp;&nbsp;Tienes: ` + infoJSON.Files + ` archivos. </br></br>` +
			`<span class="glyphicon glyphicon-save"></span>&nbsp;&nbsp;Ocupan un total de: ` + formatBytesToString(totalBytes) + `. </br></br>`
	}

	return respuesta
}
