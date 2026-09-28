# Seguridad

Si encuentro un problema de seguridad en PC Remote, no lo publico con detalles técnicos en un issue abierto. Primero lo reporto de forma privada al responsable del repositorio, indicando:

- Qué componente está afectado.
- Cómo reproducir el problema sin incluir contraseñas, tokens, direcciones privadas ni archivos personales.
- Qué impacto puede tener.
- Qué versión estaba usando.

No subo nunca `pc_remote_auth.json`, `pc_remote_instance.json`, logs, capturas con direcciones, tokens, hashes de contraseñas, archivos de configuración local ni claves privadas.

PC Remote debe usarse únicamente en computadores propios o con autorización expresa. Para conexiones remotas recomiendo una red privada como Tailscale y no exponer directamente el puerto del servidor a Internet.
