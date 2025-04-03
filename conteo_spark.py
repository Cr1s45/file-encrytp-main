from pyspark.sql import SparkSession
from pymongo import MongoClient
import json

# Configuración de PySpark
spark = SparkSession.builder \
    .appName("OnResoluteConteo") \
    .getOrCreate()

# Función para procesar los datos y realizar el conteo
def procesar_datos_spark():
    # Conexión a MongoDB
    client = MongoClient('mongodb://localhost:27017/')
    db = client['av_db']
    encuestas = db['encuestas']

    # Leer los datos de MongoDB
    datos = list(encuestas.find())

    # Convertir los datos a un formato que Spark pueda leer
    datos_json = json.dumps(datos)
    rdd = spark.sparkContext.parallelize([datos_json])
    df = spark.read.json(rdd)

    # Explode la columna de preguntas para trabajar con cada pregunta por separado
    df_exploded = df.withColumn("pregunta", explode("preguntas"))

    # Filtrar la segunda pregunta
    df_filtrado = df_exploded.filter(df_exploded.pregunta.texto == "¿Recomendarías nuestro servicio?")

    # Contar las respuestas "Sí" y "No"
    conteo = df_filtrado.groupBy("pregunta.respuesta").count()

    # Mostrar el resultado
    conteo.show()

# Ejecutar la función
procesar_datos_spark()
