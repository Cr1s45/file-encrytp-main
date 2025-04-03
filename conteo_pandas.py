from pymongo import MongoClient
import pandas as pd

# Conexión a MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['av_db']
encuestas = db['encuestas']

# Leer los datos de MongoDB
datos = list(encuestas.find())

# Convertir los datos a un DataFrame de pandas
df = pd.json_normalize(datos, record_path='preguntas', meta=['_id', 'nombre', 'fecha_creacion'])

# Filtrar la segunda pregunta
df_filtrado = df[df['texto'] == "¿Recomendarías nuestro servicio?"]

# Contar las respuestas "Sí" y "No"
conteo = df_filtrado['respuesta'].value_counts()

# Mostrar el resultado
print(conteo)
