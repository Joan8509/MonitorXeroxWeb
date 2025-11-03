# 🖨️ MonitorXeroxWeb

**MonitorXeroxWeb** es una aplicación web desarrollada en **Python (Flask)** para monitorear en tiempo real los consumibles y el estado de impresoras **Xerox** en red (modelos **B415**, **B7135**, **B8155** y **C415**).  
Permite visualizar niveles de tóner, tambores, fusores, transfer rollers, contenedores de tóner residual y exportar reportes en Excel.  
Incluye autenticación local con SQLite y una interfaz web moderna, todo desde un solo entorno.

---

## 🚀 Características

- 🔒 Sistema de autenticación (login, logout, edición de cuenta)
- 🌐 Interfaz web limpia y responsive (HTML + CSS + JS)
- 🖨️ Lectura SNMP directa sin Selenium (compatible con B415, B7135, B8155, C415)
- ⚡ Consulta múltiple de impresoras simultánea (ThreadPoolExecutor)
- 📊 Exportación a Excel con formato y barras de progreso (`openpyxl`)
- 💾 Configuración mediante archivo `.env`
- 🧱 Estructura modular optimizada para Visual Studio Code

---

## 🗂️ Estructura del proyecto

MonitorXeroxWeb/
│
├── run.py # Arranque del servidor Flask
├── requirements.txt # Dependencias del proyecto
├── .env # Variables de entorno (configuración)
│
├── app/
│ ├── init.py # Carga la app Flask
│ ├── routes.py # Rutas y APIs principales
│ ├── auth.py # Gestión de usuarios (login, cuenta)
│ ├── snmp_utils.py # Lógica SNMP
│ ├── export_xlsx.py # Generación de reportes Excel
│ └── templates/
│ ├── home.html # Página principal
│ ├── login.html # Página de acceso
│ └── account.html # Edición de cuenta
│
├── auth.db # Base de datos SQLite de usuarios
└── README.md # Documentación del proyecto

