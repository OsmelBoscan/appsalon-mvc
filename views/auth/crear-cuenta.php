<h1 class="nombre-pagina">CREAR CUENTA</h1>
<p class="descriocion-pagina">Llena el siguiente formulario para crear una cuenta</p>

<?php 
    include_once __DIR__ . "/../templates/alertas.php";

?>

<form class="formulario" method="POST" action="/crear-cuenta">
    <div class="campo">
        <label for="nombre">Nombre</label>
        <input 
        type="text" 
        id="nombre" 
        name="nombre" 
        placeholder="Tu Nombre"
        value="<?php echo s($usuario->nombre); ?>">
    </div>
    <div class="campo">
        <label for="nombre">Apellido</label>
        <input 
        type="text" 
        id="apellido" 
        name="apellido" 
        placeholder="Tu Apellido"
        value="<?php echo s($usuario->apellido); ?>">
    </div>
    <div class="campo">
        <label for="nombre">Telefono</label>
        <input 
        type="tel" 
        id="telefono" 
        name="telefono" 
        placeholder="Tu Telefono"
        value="<?php echo s($usuario->telefono); ?>">
    </div>
    <div class="campo">
        <label for="email">Email</label>
        <input 
        type="email" 
        id="email" 
        name="email" 
        placeholder="Tu Email"
        value="<?php echo s($usuario->email); ?>">>
    </div>
    <div class="campo">
        <label for="password">Password</label>
        <input 
        type="password" 
        id="password" 
        name="password" 
        placeholder="Tu Password">
    </div>

    <input type="submit" class="boton boton-verde" value="Crear Cuenta">

</form>

<div class="acciones">
    <a href="/">¿Ya tienes una cuenta? Inicia Sesion</a>
    <a href="/olvide">¿Olvidaste tu password?</a>
</div>