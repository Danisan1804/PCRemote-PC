# PC Remote

PC Remote es el proyecto que estoy haciendo para controlar mi computador desde el celular mediante una interfaz web. La idea es poder consultar la pantalla, manejar el teclado y el mouse, revisar el estado del equipo y transferir archivos sin tener que estar frente al PC.

## Qué puedo hacer

Desde la interfaz puedo:

- Ver la pantalla del computador.
- Mover el mouse y enviar clics.
- Enviar texto y teclas.
- Consultar CPU, memoria, disco, batería y tiempo de actividad.
- Revisar y cerrar procesos permitidos.
- Bloquear, reiniciar, apagar o cancelar una orden de energía.
- Navegar por las unidades del PC.
- Subir y descargar archivos.
- Activar y detener la cámara de forma visible.
- Usar un asistente local con Ollama, sin depender de una API de pago.

La interfaz móvil también incluye una PWA para guardar conexiones en el propio dispositivo. No hay una cuenta central ni un registro de usuarios.

## Cómo está organizado

- `server.py`: servidor FastAPI y versión principal de la interfaz.
- `pc_remote_launcher.pyw`: inicia el servidor sin abrir una consola visible.
- `iniciar.bat`: arranque manual.
- `INSTALAR.bat`: instalación tradicional desde el código fuente.
- `DESINSTALAR.bat`: elimina el arranque automático de esa instalación.
- `pwa/`: interfaz móvil instalable y panel de control.
- `installer/`: instalador gráfico para Windows y sus términos de seguridad.
- `requirements.txt`: dependencias de Python.
- `installer/build_installer.bat`: genera el instalador de Windows.

La versión actual es `server.py`. No uso `lll.py`, porque corresponde a una versión anterior y no forma parte del repositorio público.

## Seguridad y datos locales

Cada instalación crea su propia contraseña de PC Remote. No es la contraseña de Windows y no se envía a un servicio central.

Las credenciales se guardan localmente en `pc_remote_auth.json` usando PBKDF2-SHA256 para las contraseñas nuevas. La identidad local de la instalación se guarda en `pc_remote_instance.json`. Esos archivos están excluidos por `.gitignore` y nunca deben subirse.

Las sesiones tienen vencimiento y las APIs protegidas requieren cookie de sesión o token Bearer. La PWA guarda sus conexiones localmente en el navegador. Para acceder desde fuera de la red local uso una red privada, preferiblemente Tailscale; no recomiendo abrir directamente el puerto del servidor a Internet.

La cámara solo se activa cuando la solicito y tiene controles visibles para iniciarla y detenerla. El proyecto no está diseñado para ocultar indicadores de cámara o micrófono.

## Ejecutar desde el código fuente

Necesito Windows y Python instalado. Desde la carpeta del proyecto creo el entorno e instalo las dependencias:

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
```

Después puedo iniciar el servidor con:

```bat
iniciar.bat
```

El servidor utiliza el puerto `8000` y queda disponible en la dirección del PC dentro de la red configurada. La primera instalación debe crear una contraseña local antes de aceptar conexiones.

## Instalador de Windows

El instalador gráfico está en `installer/setup_gui.py`. Muestra los términos, explica los permisos, permite elegir la carpeta de instalación y solicita una contraseña nueva para esa copia.

Para generar el ejecutable:

```bat
installer\build_installer.bat
```

El resultado queda en `dist/PCRemoteSetup.exe`. La carpeta `dist` y el ejecutable están excluidos del repositorio para no subir binarios generados ni entornos virtuales. Si más adelante publico un instalador, lo haré como un artefacto o una versión de GitHub Release después de revisarlo.

El instalador copia el servidor, la PWA y el entorno de Python; crea una identidad local, guarda la contraseña configurada y registra `PCRemoteLauncher` para iniciar el servicio al iniciar sesión en Windows. También comprueba si Tailscale está instalado y conectado.

## PWA y conexiones

La PWA se puede abrir desde `/pwa/` en una instalación de PC Remote. Desde allí puedo:

1. Agregar un nombre para el PC.
2. Escribir la dirección que usaré dentro de mi red privada.
3. Comprobar que el servidor, la contraseña local y Tailscale estén listos.
4. Iniciar sesión y guardar la conexión en ese dispositivo.
5. Abrir el panel de control, cerrar la sesión o eliminar la conexión.

La dirección no se muestra en las tarjetas de conexión, pero sigue siendo un dato local del navegador. Ocultarla en la interfaz no significa que sea técnicamente imposible verla en el dispositivo del usuario.

Si alojo la PWA en otro origen, configuro únicamente el origen exacto mediante `PCREMOTE_PWA_ORIGINS`. No uso CORS abierto para cualquier sitio y mantengo la conexión dentro de una red privada con HTTPS cuando sea posible.

## Asistente local

El asistente puede usar Ollama en el propio PC. La dirección predeterminada es `http://localhost:11434` y el modelo se puede cambiar con `PCREMOTE_LOCAL_MODEL`.

Si Ollama no está disponible, el servidor usa una interpretación básica para algunas acciones de energía. La voz depende de las capacidades y permisos del navegador; si no funciona, puedo escribir el comando manualmente.

## Comprobaciones realizadas

He comprobado que:

- `server.py` y el instalador compilan.
- Los scripts JavaScript de la PWA tienen sintaxis válida.
- El estado público y los recursos de la PWA responden correctamente.
- Una instalación temporal extrae `venv` en la ruta correcta.
- Una instalación temporal puede iniciar sesión y consultar una API protegida.
- El instalador se puede abrir sin dejarlo ejecutándose.

La prueba de instalación temporal no registra tareas de Windows ni conserva archivos después de terminar.

## Qué falta antes de una publicación amplia

Antes de distribuirlo públicamente todavía debo revisar los textos legales, probarlo con varios computadores, verificar la configuración de HTTPS y preparar un proceso de actualizaciones. También debo revisar las reglas de la tienda si convierto la PWA en una aplicación para Android.

## Licencia

Todavía no he elegido una licencia definitiva para este proyecto. Antes de publicarlo como software reutilizable debo definirla y añadir el archivo correspondiente.
