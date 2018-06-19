package main

import "github.com/dtylman/gowd"

func vistaLogin() string {
	return `<div class="container">
		<div class="row">
			<div class="col-md-6 col-md-offset-3">
				<div class="panel panel-login">
					<div class="panel-heading">
						<div class="row">
							<div class="col-xs-6">
								<a id="login-form-link" href="#" class="active">Iniciar Sesión</a>
							</div>
							<div class="col-xs-6">
								<a id="register-form-link" href="#">Registro</a>
							</div>
						</div>
						<hr>
					</div>
					<div class="panel-body">
						<div class="row">
							<div class="col-lg-12">
								<div id="login-form">
									<div class="form-group">
										<input type="text" id="usuario" class="form-control" placeholder="Usuario" autocomplete="new-password">
									</div>
									<div class="form-group">
										<input type="password" id="contraseña" class="form-control" placeholder="Contraseña" autocomplete="new-password">
									</div>
									<div class="form-group">
										<button id="login-submit" class="form-control btn btn-login">Iniciar Sesión</button>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>`
}

func vistaRegister() string {
	return `<div class="container">
		<div class="row">
			<div class="col-md-6 col-md-offset-3">
				<div class="panel panel-login">
					<div class="panel-heading">
						<div class="row">
							<div class="col-xs-6">
								<a id="login-form-link" href="#">Iniciar Sesión</a>
							</div>
							<div class="col-xs-6">
								<a id="register-form-link" href="#" class="active">Registro</a>
							</div>
						</div>
						<hr>
					</div>
					<div class="panel-body">
						<div class="row">
							<div class="col-lg-12">
								<div id="register-form">
									<div class="form-group">
										<input type="text" id="registerUser" class="form-control" placeholder="Username" autocomplete="off">
									</div>
									<div class="form-group">
										<input type="email" id="registerEmail" class="form-control" placeholder="Email" autocomplete="off">
									</div>
									<div class="form-group">
										<input type="password" id="registerPassword" class="form-control" placeholder="Password" autocomplete="off">
									</div>
									<div class="form-group">
										<input type="password" id="confirmPassword" class="form-control" placeholder="Confirm Password" autocomplete="off">
									</div>
									<div class="form-group">
										<button id="register-submit" class="form-control btn btn-register">Regístrate ya!</button>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>`
}

func vistaPrincipal() string {
	return `<header class="main-header"><nav class="navbar navbar-static-top" style="background-color:#FF654E">
		<div class="container-fluid">
			<div class="navbar-header" style="margin-right: 0; margin-left: 0;">
				<button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar-collapse">
					<i class="fa fa-bars"></i>
				</button>
				<a class="navbar-left" href="#" id="recargar"><img style="max-height: 45px;margin-right: 15px;" src="assets/img/logo_alargado2.png"/></a>
			</div>
			<div class="collapse navbar-collapse" id="navbar-collapse">
				<ul class="nav navbar-nav">
				<li class="active"><a href="#">Almacenamiento <span class="sr-only">(current)</span></a></li>
				</ul>
				<ul class="nav navbar-nav navbar-right" style="margin-right: 15px;">
				<li><a style="color: #fff;user-select: none;" id="binvenido"> Bienvenido/a ` + login + ` !</a></li>
				<li class="dropdown">
					<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">Ajustes <span class="caret"></span></a>
					<ul class="dropdown-menu dropdown-menu-settings" style="background-color: #FF654E">
					<li><a id="ajustes" href="#">Cambiar ajustes</a></li>
					<li role="separator" class="divider"></li>
					<li><a href="#" id="logout-link"><i class="icon-off"></i>Cerrar sesión</a></li>
					</ul>
				</li>
				</ul>
			</div>
		</div>
	</nav></header>
	<div class="content-wrapper" style="min-height:unset;">
		</br>
		<div class="row" style="margin: 0 auto;">
			<div class="col-sm-3 col-md-3">
				<div class="row">
					<div class="col-sm-12 col-md-12">
						<div class="box box-primary">
							<div class="box-header">
								<h3 class="box-title">Gintónico</h3>
							</div>
							<div class="box-body">
								<input type="file" id="idFile" onchange="subirArchivo()" style="display: none"/>
								<input type="text" id="route" style="display: none" />
								<input type="text" id="filename" style="display: none" />
								<input type="button" onclick="document.getElementById('idFile').click();"  value="Subir Archivo" id="file-selector" class="btn btn-primary btn-block btn-principal"/>
								<button type="button"  style="display: none"id="buttonEnviar"  class="btn btn-primary btn-block"> Subir </button>
								<button type="button"  style="display: none" id="buttonPedir" class="btn btn-primary btn-block">Pedir</button>
								<input type="text" id="archivoPedido" style="display: none" />
									
								<div class="clearfix"></div>
							</div>
						</div>
					</div>
				</div>
				<div class="row">
					<div class="col-sm-12 col-md-12">
						<div class="box box-primary">
							<div class="box-header">
								<h3 class="box-title">Información</h3>
							</div>
							<div class="box-body" style="padding-left: 25px;">
								` + getInfo() + `
							</div>
						</div>
					</div>
				</div>
			</div>
			<div class="col-sm-9 col-md-9" style="margin-bottom: 40px;">
				<div class="box box-primary">
					<div class="box-header">
						<h3 class="box-title">Ficheros</h3>
					</div>
					<div class="box-body">
						<table id="tabla" class="table table-striped table-bordered dataTable no-footer" style="width:100%">
							<thead>
								<tr>
									<th>Archivo</th>
									<th class="sizeColumn" style="width:130px">Tamaño</th>
								</tr>
							</thead>
							<tbody>
								<button type="button" id="buttonEliminar" style="display: none" class="btn btn-primary btn-block">Pedir</button>
								<input type="text" id="archivoEliminar" style="display: none" />
								` + peticionNombreFicheros() + `
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</div>
	<footer class="main-footer" style="bottom:0;position:fixed;width:100%">
		<div class="container">
			<div class="pull-right hidden-xs">
				<b>Version: </b>&nbsp;1.0.0
			</div>
			<strong>Copyright © 2018&nbsp;<a href="#" style="color:#FF654E"> Gintónico </a>.</strong>&nbsp;&nbsp;&nbsp;Todos los derechos reservados.
		</div>
	</footer>
	`
}

func vistaFactor() string {
	return `<div class="container">
		<div class="row">
			<div class="col-md-6 col-md-offset-3">
				<div class="panel panel-login">
					<div class="panel-heading">
						<div class="row">
							<div class="col-xs-6">
								<a id="login-form-link" href="#" class="active">Iniciar Sesión</a>
							</div>
							<div class="col-xs-6">
								<a id="register-form-link" href="#">Registro</a>
							</div>
						</div>
						<hr>
					</div>
					<div class="panel-body">
						<div class="row">
							<div class="col-lg-12">
								<div id="login-form">
									<div class="form-group">
										<input type="text" id="codigo" class="form-control" placeholder="Introduzca el codigo enviado por email" autocomplete="unset">
									</div>
									<div class="form-group">
										<button id="login-submit" class="form-control btn btn-login">Iniciar Sesión</button>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>`
}

func vistaAjustes() string {
	return `<header class="main-header"><nav class="navbar navbar-static-top" style="background-color:#FF654E">
		<div class="container-fluid">
			<div class="navbar-header" style="margin-right: 0; margin-left: 0;">
				<button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar-collapse">
					<i class="fa fa-bars"></i>
				</button>
				<a class="navbar-left" href="#" id="recargar"><img style="max-height: 45px;margin-right: 15px;" src="assets/img/logo_alargado2.png"/></a>
			</div>
			<div class="collapse navbar-collapse" id="navbar-collapse">
				<ul class="nav navbar-nav">
				<li class="active"><a href="#">Ajustes <span class="sr-only">(current)</span></a></li>
				</ul>
				<ul class="nav navbar-nav navbar-right" style="margin-right: 15px;">
				<li><a style="color: #fff;user-select: none;" id="binvenido"> Bienvenido/a ` + login + ` !</a></li>
				<li class="dropdown">
					<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">Ajustes <span class="caret"></span></a>
					<ul class="dropdown-menu dropdown-menu-settings" style="background-color: #FF654E">
					<li><a id="ajustes" href="#">Cambiar ajustes</a></li>
					<li role="separator" class="divider"></li>
					<li><a href="#" id="logout-link"><i class="icon-off"></i>Cerrar sesión</a></li>
					</ul>
				</li>
				</ul>
			</div>
		</div>
	</nav></header>
	<div class="content-wrapper" style="min-height:unset;">
		</br>
		<div class="row" style="margin: 0 auto;">
			<div class="col-sm-3 col-md-3">
			</div>
			<div class="col-sm-6 col-md-6">
				<div class="box box-primary">
					<div class="box-header">
						<h3 class="box-title">Ajustes</h3>
					</div>
					<div class="box-body panel-login"">
						<div class="form-group">
							<div class="input-group">
								<span class="input-group-addon" style="border-radius: 4px 0px 0px 4px; min-width: 90px;">Email</span>
								<input type="email" id="email" class="form-control" placeholder="Email" autocomplete="new-password">
							</div>
						</div>
						<div class="form-group" style="text-align: center;">
							<div class="checkbox">
								<label><input id="doblefactor" class="revert-input" type="checkbox" value="">&nbsp;&nbsp;Activar doble factor de autenticación (necesario email válido)</label>
							</div>
						</div>
						</br>
						<div class="form-group" style="text-align: center;">
							<button id="ajustes-submit" class="form-control btn btn-login" style="width: 40%;">Guardar cambios</button>
						</div>
					</div>
				</div>
			</div>
			<div class="col-sm-3 col-md-3">
			</div>
		</div>
	</div>
	<footer class="main-footer" style="bottom:0;position:fixed;width:100%">
		<div class="container">
			<div class="pull-right hidden-xs">
				<b>Version: </b>&nbsp;1.0.0
			</div>
			<strong>Copyright © 2018&nbsp;<a href="#" style="color:#FF654E"> Gintónico </a>.</strong>&nbsp;&nbsp;&nbsp;Todos los derechos reservados.
		</div>
	</footer>`
}

func modalNormal(titulo string, contenido string) {
	element := body.Find("modal")
	if element != nil {
		body.RemoveElement(element)
	}
	body.AddHTML(`<div id="modal"><!-- Button trigger modal -->
    <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#modalNormal" style="display: none;">
        Lanzar modal normal
    </button>

    <!-- Modal -->
    <div class="modal fade" id="modalNormal" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
				<div class="modal-header">
					<button type="button" class="close" data-dismiss="modal" aria-label="Close">
						<span aria-hidden="true" style="color: white;">×</span>
					</button>
                    <h5 class="modal-title" id="modalNormalTitulo">`+titulo+`</h5>
                </div>
                <div class="modal-body">
                    <p id="textoModal">`+contenido+`</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-primary" data-dismiss="modal">Entendido!</button>
                </div>
            </div>
        </div>
    </div></div>`, nil)
}

func modalError(titulo string, contenido string) {
	element := body.Find("modal")
	if element != nil {
		body.RemoveElement(element)
	}
	body.AddHTML(`<div id="modal"><!-- Button trigger modal -->
    <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#modalError" style="display: none;">
        Lanzar modal error
    </button>

    <!-- Modal -->
    <div class="modal modal-danger fade" id="modalError" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
				<div class="modal-header">
					<button type="button" class="close" data-dismiss="modal" aria-label="Close">
						<span aria-hidden="true" style="color: white;">×</span>
					</button>
                    <h5 class="modal-title" id="modalErrorTitulo">`+titulo+`</h5>
                </div>
                <div class="modal-body">
                    <p id="textoModal">`+contenido+`</p>
                </div>
                <div class="modal-footer">
                    <button id="entendido" type="button" class="btn btn-outline" data-dismiss="modal">Entendido!</button>
                </div>
            </div>
        </div>
    </div></div>`, nil)
}

func goLogin(sender *gowd.Element, event *gowd.EventElement) {
	mostrar = "login"
	login = ""
	token = ""
	password = ""
	main()
}

func goRegister(sender *gowd.Element, event *gowd.EventElement) {
	mostrar = "register"
	login = ""
	token = ""
	password = ""
	main()
}

func goPrincipal(sender *gowd.Element, event *gowd.EventElement) {
	mostrar = "principal"
	password = ""
	main()
}

func goDobleFactor(sender *gowd.Element, event *gowd.EventElement) {
	mostrar = "doblefactor"
	main()
}

func goAjustes(sender *gowd.Element, event *gowd.EventElement) {
	mostrar = "ajustes"
	main()
}
