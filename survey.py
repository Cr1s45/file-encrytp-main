from pymongo import MongoClient
from faker import Faker
from datetime import datetime
import random

# Configuración de la conexión a MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['av_db']
encuestas = db['encuestas']

# Inicializar Faker para generar datos ficticios
fake = Faker()

# Función para generar una encuesta ficticia
def generar_encuesta():
    return {
        "nombre": "Encuesta de satisfacción",
        "preguntas": [
            {
                "texto": "¿Cómo calificarías nuestro servicio?",
                "tipo": "escala",
                "respuesta": random.randint(1, 5)
            },
            {
                "texto": "¿Qué te gustaría mejorar?",
                "tipo": "abierta",
                "respuesta": fake.sentence()
            },
            {
                "texto": "¿Recomendarías nuestro servicio?",
                "tipo": "opcion",
                "respuesta": random.choice(["Sí", "No"])
            },
            {
                "texto": "¿Cuánto tiempo esperaste para ser atendido?",
                "tipo": "numerico",
                "respuesta": random.randint(1, 60)
            },
            {
                "texto": "¿Qué tan fácil fue agendar una cita?",
                "tipo": "escala",
                "respuesta": random.randint(1, 10)
            },
            {
                "texto": "Comentarios adicionales",
                "tipo": "abierta",
                "respuesta": fake.sentence()
            }
        ],
        "fecha_creacion": datetime.now()
    }

# Generar e insertar 50 encuestas distintas
for _ in range(50):
    encuesta = generar_encuesta()
    encuestas.insert_one(encuesta)

print("50 encuestas insertadas correctamente.")
