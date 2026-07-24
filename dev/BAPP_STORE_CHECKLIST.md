# Checklist de Aceptación para la BApp Store - Extensión Dynamic Variables

Este documento recopila los criterios de aceptación oficiales de PortSwigger para publicar extensiones en la BApp Store ([BApp Store Acceptance Criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria)) y el estado actual de cumplimiento de la extensión **Dynamic Variables**.

---

## Criterios de Aceptación y Estado de Cumplimiento

### 1. Función Única (Performs a unique function)
- **Criterio**: No duplicar la funcionalidad exacta de una extensión existente en la BApp Store.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**: Dynamic Variables proporciona gestión avanzada de variables dinámicas entre peticiones y respuestas (extracción multi-fuente por Regex/JSON/Header/Body, auto-reemplazo en Repeater/Intruder/Proxy/Scanner con sintaxis personalizable, refresco en cascada/staged y persistencia por proyecto).

---

### 2. Nombre Claro y Descriptivo (Has a clear, descriptive name)
- **Criterio**: El nombre debe describir claramente la función de la extensión.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - Nombre configurado en código: `api.extension().setName("Dynamic Variables");` en `src/main/java/burp/DynamicVariables.java`.
  - Incluye `README.md` con descripción clara y guía de uso.

---

### 3. Operación Segura (Operates securely)
- **Criterio**: Tratar el contenido de los mensajes HTTP como no confiable (*untrusted*). Evitar que la extensión exponga al usuario a ataques o ejecuciones de código no deseadas.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - Extracción de Regex/JSON mediante parsers seguros y con manejo estricto de excepciones sin eval ni invocación de intérpretes de comandos externos.
  - Sanitización en codificación de estado (`VariableStateCodec`).

---

### 4. Inclusión de Todas las Dependencias (Includes all dependencies)
- **Criterio**: La extensión no debe requerir descargas o librerías externas adicionales en tiempo de ejecución.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - `build.gradle` utiliza solo `montoya-api:2026.7` como `compileOnly` (proporcionada por el núcleo de Burp Suite) y bibliotecas estándar de Java.

---

### 5. Uso de Hilos para Mantener la Reactividad (Uses threads to maintain responsiveness)
- **Criterio**: No realizar operaciones lentas (como peticiones HTTP) en el Swing Event Dispatch Thread (EDT). Capturar y registrar excepciones de hilos de fondo en el error stream (`api.logging().logToError(...)`). Evitar bloqueos (*deadlocks*).
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - Las peticiones de refresco síncrono y prueba de reglas se ejecutan dentro de hilos separados (`new Thread(...)`).
  - Las actualizaciones de interfaz utilizan `SwingUtilities.invokeLater(...)`.
  - Las excepciones en hilos secundarios capturan el trace y registran a `api.logging().logToError(...)`.

---

### 6. Descarga Limpia de Recursos (Unloads cleanly)
- **Criterio**: Registrar un manejador de descarga vía `Extension.registerUnloadingHandler()` para liberar hilos, listeners y recursos.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - En `src/main/java/burp/DynamicVariables.java` se registra el handler de `registerUnloadingHandler`.

---

### 7. Uso de la Red de Burp (Uses Burp networking)
- **Criterio**: Hacer peticiones HTTP a través de `api.http().issueHttpRequest()` en lugar de librerías como `java.net.URL` o `HttpClient`.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - Toda emisión de peticiones HTTP de refresco automático utiliza `api.http().issueHttpRequest(...)`. Esto garantiza el respeto de proxys upstream, reglas de sesión y configuraciones globales de Burp.
  - No realiza llamadas de red en audit pasivo (`ScanCheck.passiveAudit()`).

---

### 8. Soporte para Trabajo Offline (Supports offline working)
- **Criterio**: Las extensiones deben operar sin requerir conexión a internet para descargar reglas o definiciones externas.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - La extensión es 100% autónoma. No depende de servidores o servicios online externos.

---

### 9. Capacidad para Proyectos Grandes (Can cope with large projects)
- **Criterio**: Evitar mantener referencias de largo plazo a objetos pesados (`HttpRequestResponse`, historial completo de Proxy). Si se necesita guardar un mensaje HTTP de forma duradera, usar la API de persistencia o datos mínimos necesarios.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - `src/main/java/burp/LatestRequestTracker.java` limita en memoria los últimos rastreos por herramienta/herramienta objetivo.
  - Las reglas de extracción almacenan únicamente la plantilla de la petición en Base64 o estructuras livianas en lugar de mantener objetos vivos de la historia de Burp.

---

### 10. Ventanas Padre para Elementos GUI (Provides a parent for GUI elements)
- **Criterio**: Elementos flotantes, cuadros de diálogo y popups deben tener como ventana padre la ventana principal de Burp (`api.userInterface().swingUtils().suiteFrame()`).
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - Todos los `JDialog` y `JOptionPane` en `VariableContextMenuProvider.java` y `VariableManager.java` especifican `suiteFrame()`, `mainPanel` o `dialog` como su ventana contenedora padre.

---

### 11. Uso del Artefacto Montoya API (Uses the Montoya API artifact)
- **Criterio**: Referenciar el artefacto `montoya-api` mediante Gradle o Maven.
- **Estado**: **CUMPLE**
- **Detalle / Verificación**:
  - Configurado en `build.gradle` como `net.portswigger.burp.extensions:montoya-api:2026.7`.

---

### 12. Proveedor de IA Predeterminado de Burp (Uses Burp AI as the default AI provider)
- **Criterio**: Si la extensión incluye funcionalidades de IA, debe utilizar Burp AI por defecto.
- **Estado**: **NO APLICA (N/A)**
- **Detalle / Verificación**:
  - La extensión no hace uso de Inteligencia Artificial ni modelos de lenguaje en la versión actual.

---

## Lista de Verificación (Checklist) para Desarrollos y Cambios Futuros

Al realizar modificaciones en la extensión, asegúrate de verificar lo siguiente antes de compilar y enviar a la BApp Store:

- [ ] **Compilación & Tests**: El proyecto compila sin advertencias ni errores (`./gradlew test`).
- [ ] **Sin Hilos Bloqueados en Swing**: Ninguna petición HTTP o tarea de I/O se ejecuta en el Event Dispatch Thread (EDT).
- [ ] **Log de Excepciones**: Los bloques `catch` en hilos secundarios reportan el stacktrace usando `api.logging().logToError(...)`.
- [ ] **Diálogos Modal/Popups**: Todos los `JDialog`, `JOptionPane`, `JFileChooser` creados tienen como padre `api.userInterface().swingUtils().suiteFrame()`.
- [ ] **Requisitos de Red**: Todas las peticiones HTTP externas utilizan `api.http().issueHttpRequest(...)`.
- [ ] **Limpieza de Recursos**: En `registerUnloadingHandler`, se liberan adecuadamente hilos/recursos activos.
- [ ] **Gestión de Memoria**: No se conservan referencias duraderas a grandes colecciones de `HttpRequestResponse`.
