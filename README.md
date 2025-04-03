﻿# Flie-Encrytp

Primero clonar repocitorio

En su lap, deen tener MongoDB inicado con una base de datos `av_db`con tres colecciónes:
- `encuestas`
- `usuarios`
- `archivos`

Antes de ejecutar la app, debe instalar las dependencias:
`pip install -r requirements.txt`

Para inicar la aplicación deben irse a la terminal, dentro de la ruta de la carpeta del proyecto:
`python app.py`

En el navegador deben entrar a `127.0.0.1:5000/`

Va a dirigir a la pagina de inicio, como la base de datos es nueva, debe registrar un nuevo usuario.

En la base de datos van a cambiar el `rol` del usuario que acaba de registrar, debe cambiarlo de `user` a `admin`

Despues de be iniciar sesión con ese usuario, para dirigirte al `Panel de Adminstración`

Si no cambia este atributo en la base de datos, va a dirigir al `Panel de Usuario` y no te dajará desencryptar.

---

Si quiere probar el conteo con `pandas` y `spark` primero deben crear un entorno virtual:
`python -m venv venv`
`venv\Scripts\activate`

Dentro del entorno virtual debe instalar las dependencias:
`pip install pymongo numpy pyspark pandas`

Una vez isntaladas, para ejecutar primero con spark:
`spark-submit conteo_spark.py`

Con pandas:
`python conteo_pandas.py`

---

Eso es todo por el momento, si tene dudas, pregunta.

<<<<<<< HEAD
Contenido local
=======
Contenido remoto
>>>>>>> 76e58e8aa938956ca3c075c9bce7e42774986d1c