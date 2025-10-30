# 🖨️ MonitorXeroxWeb

**MonitorXeroxWeb** es una aplicación web desarrollada en **Python (Flask)** para monitorear en tiempo real los consumibles y estados de impresoras **Xerox** en red (modelos B415, B7135, B8155, C415, entre otros).  
Permite visualizar porcentajes de tóner, tambores, unidades de imagen, contenedores de tóner residual, generar reportes en Excel y gestionar cuentas de usuario mediante autenticación segura (SQLite).

---

## 🚀 Características principales

- 🔒 Sistema de autenticación con SQLite y `werkzeug.security`
- 🌐 Interfaz web moderna (HTML + CSS + JS integrados)
- 🖨️ Consulta SNMP en múltiples impresoras simultáneamente
- 📊 Exportación de reportes a Excel (`openpyxl`)
- 💾 Configuración mediante archivo `.env`
- 🧩 Estructura modular compatible con Visual Studio Code

---

## 🗂️ Estructura del proyecto

MonitorXeroxWeb/
│
├── run.py # Punto de entrada Flask
├── requirements.txt # Dependencias del proyecto
├── .env # Variables de entorno (NO subir a GitHub)
├── .gitignore # Archivos a excluir del repositorio
│
├── app/
│ ├── init.py # Inicializa la app Flask
│ ├── routes.py # Rutas y controladores principales
│ ├── auth.py # Gestión de usuarios y login
│ ├── snmp_utils.py # Consultas SNMP a impresoras
│ └── export_xlsx.py # Generación de reportes Excel
│
└── templates/
├── home.html # Panel principal
├── login.html # Página de inicio de sesión
└── account.html # Configuración de cuenta

▶️ Ejecución del proyecto
python run.py


