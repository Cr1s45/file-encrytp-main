from flask import Flask, get_flashed_messages, render_template, send_file, request, redirect, url_for, send_from_directory, flash, jsonify, abort
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from bson import ObjectId
from gridfs import GridFS
from io import BytesIO
from cryptography.fernet import Fernet
import re
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

app = Flask(__name__)
app.secret_key = 'una_clave_secreta_muy_segura_y_unica'

# Configuración de MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/file_encrypt_db"
mongo = PyMongo(app)
fs = GridFS(mongo.db) 

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"
app.config['REMEMBER_COOKIE_DURATION'] = 3600

# Clave para encriptación
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Modelo de usuario
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id  
        self.username = username

    @staticmethod
    def get(user_id):
        user_data = mongo.db.usuarios.find_one({'_id': ObjectId(user_id)})
        if not user_data:
            return None
        return User(user_id=user_id, username=user_data['username'])
    

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def convertir_tamaño(tamaño_bytes):
    """Convierte bytes a un formato legible (KB, MB, GB)"""
    for unidad in ['B', 'KB', 'MB', 'GB']:
        if tamaño_bytes < 1024:
            return f"{tamaño_bytes:.2f} {unidad}"
        tamaño_bytes /= 1024
    return f"{tamaño_bytes:.2f} TB"

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

def limpiar_nombre_archivo(texto):
    return re.sub(r'[<>:"/\\|?*]', '', texto)

# Ruta para el login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = mongo.db.usuarios.find_one({'username': username})
        
        if user_data and check_password_hash(user_data['password'], password):
            user_obj = User(user_id=str(user_data['_id']), username=user_data['username'])
            login_user(user_obj)
            

            print(f"Usuario autenticado: {user_data['username']}, Rol: {user_data.get('role')}")
            
        
            if user_data.get('role') == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('panel_user'))
        
        flash('Usuario o contraseña incorrectos', 'error')
    return render_template('login.html')

# Ruta para registrar nuevos usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user') 
        existing_user = mongo.db.usuarios.find_one({'username': username})
        if existing_user:
            flash('El usuario ya existe. Por favor, inicia sesión.', 'warning')
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(password)
    
        mongo.db.usuarios.insert_one({
            'username': username,
            'password': hashed_password, 
            'role': role  
        })
       
        return redirect(url_for('login'))
    flashed_messages = get_flashed_messages(with_categories=True)
    filtered_messages = [(category, message) for category, message in flashed_messages 
                         if category in ['success', 'warning']]
    return render_template('register.html', messages=filtered_messages)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente', 'success')
    return redirect(url_for('home'))

# Rutas principales
@app.route('/')
def home():
    return render_template('index.html')
@app.route('/panel_user')
@login_required
def panel_user():
    if current_user.is_authenticated:
        user = mongo.db.usuarios.find_one({'_id': ObjectId(current_user.id)})
        
        if user:
         
            archivos = list(mongo.db.archivos.find({'usuario': user['username']}))
            total_archivos = len(archivos)
            total_encriptados = len([archivo for archivo in archivos if archivo.get('encriptado', False)])
            total_no_encriptados = total_archivos - total_encriptados
            

            archivos_recientes = sorted(archivos, 
                                      key=lambda x: x['fecha_subida'], 
                                      reverse=True)[:5]
            
            return render_template('panel_user.html', 
                                 username=user['username'],
                                 user_role=user.get('role', 'user'),  
                                 total_archivos=total_archivos,
                                 total_encriptados=total_encriptados,
                                 total_no_encriptados=total_no_encriptados,
                                 archivos_recientes=archivos_recientes)
    
   
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin():
    if current_user.is_authenticated:
    
        user = mongo.db.usuarios.find_one({'_id': ObjectId(current_user.id)})
        
        if user and user.get('role') == 'admin':  
          
            total_archivos = mongo.db.archivos.count_documents({})
            total_usuarios = mongo.db.usuarios.count_documents({})
            total_encuestas = mongo.db.encuestas.count_documents({})
            
        
            archivos_recientes = list(mongo.db.archivos.find()
                                    .sort('fecha_subida', -1)
                                    .limit(5))
            
            return render_template('admin.html',
                                username=user['username'],
                                user_role=user['role'],
                                total_archivos=total_archivos,
                                total_usuarios=total_usuarios,
                                total_encuestas=total_encuestas,
                                archivos_recientes=archivos_recientes,
                                is_admin=True)
        
       
        flash('No tienes permisos para acceder a esta página', 'error')
        return redirect(url_for('panel_user'))
    return redirect(url_for('login'))

@app.route('/archive')
@login_required
def archive():
    try:
     
        user_data = mongo.db.usuarios.find_one({'username': current_user.username})
        if not user_data:
            flash('Usuario no encontrado', 'error')
            return redirect(url_for('panel_user'))
        
      
        archivos = list(mongo.db.archivos.find({'usuario': current_user.username}))
        
        return render_template(
            'archive.html',
            archivos=archivos,
            username=current_user.username,
            user_role=user_data.get('role', 'user'), 
            convertir_tamaño=convertir_tamaño
        )
    except Exception as e:
        app.logger.error(f"Error al cargar archivos: {str(e)}")
        flash('Error al cargar los archivos', 'error')
        return redirect(url_for('panel_user'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No se seleccionó archivo', 'error')
        return redirect(url_for('archive'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Nombre de archivo vacío', 'error')
        return redirect(url_for('archive'))
    
    try:
        filename = secure_filename(file.filename)
        file_data = file.read()
        
      
        file_id = fs.put(
            BytesIO(file_data),
            filename=filename,
            content_type=file.content_type  
        )
        
      
        mongo.db.archivos.insert_one({
            'nombre': filename,
            'file_id': file_id,
            'fecha_subida': datetime.now(),
            'tamaño': len(file_data),
            'encriptado': False,  
            'usuario': current_user.username,
            'content_type': file.content_type  
        })
        
        flash('Archivo subido correctamente', 'success')
        return redirect(url_for('archive'))
    
    except Exception as e:
        flash(f'Error al subir archivo: {str(e)}', 'error')
        return redirect(url_for('archive'))
    
# Ruta para ver archivos
@app.route('/view/<file_id>')
@login_required
def view_file(file_id):
    try:
        # Verificar que el archivo pertenece al usuario actual
        archivo = mongo.db.archivos.find_one({
            '_id': ObjectId(file_id),
            'usuario': current_user.username
        })
        
        if not archivo:
            abort(404, description="Archivo no encontrado o no tienes permisos")
        
        # Obtener el archivo de GridFS
        grid_file = fs.get(archivo['file_id'])
        file_data = grid_file.read()
        
        # Desencriptar si es necesario
        if archivo['encriptado']:
            file_data = cipher_suite.decrypt(file_data)
        
        # Crear un objeto BytesIO con los datos del archivo
        file_stream = BytesIO(file_data)
        file_stream.seek(0)
        
        # Enviar el archivo con el tipo MIME correcto
        return send_file(
            file_stream,
            mimetype=archivo.get('content_type', 'application/octet-stream'),
            as_attachment=False,
            download_name=archivo['nombre']
        )
    
    except Exception as e:
        app.logger.error(f"Error al ver archivo {file_id}: {str(e)}")
        abort(404, description="Error al procesar el archivo")

# Ruta para descargar archivos
@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    try:
        # Verificar que el archivo pertenece al usuario actual
        archivo = mongo.db.archivos.find_one({
            '_id': ObjectId(file_id),
            'usuario': current_user.username
        })
        
        if not archivo:
            abort(404, description="Archivo no encontrado o no tienes permisos")
        
        # Obtener el archivo de GridFS
        grid_file = fs.get(archivo['file_id'])
        file_data = grid_file.read()
        
        # Desencriptar si es necesario
        if archivo['encriptado']:
            file_data = cipher_suite.decrypt(file_data)
        
        # Crear un objeto BytesIO con los datos del archivo
        file_stream = BytesIO(file_data)
        file_stream.seek(0)
        
        # Enviar el archivo como descarga
        return send_file(
            file_stream,
            mimetype=archivo.get('content_type', 'application/octet-stream'),
            as_attachment=True,
            download_name=archivo['nombre']
        )
    
    except Exception as e:
        app.logger.error(f"Error al descargar archivo {file_id}: {str(e)}")
        abort(404, description="Error al descargar el archivo")

# Ruta para encriptar/desencriptar archivos
@app.route('/toggle_encrypt/<file_id>', methods=['POST'])
@login_required
def toggle_encrypt(file_id):
    try:
        # Verificar que el archivo pertenece al usuario actual
        archivo = mongo.db.archivos.find_one({
            '_id': ObjectId(file_id),
            'usuario': current_user.username
        })
        
        if not archivo:
            return jsonify({'success': False, 'message': 'Archivo no encontrado'}), 404
        
        # Obtener el archivo de GridFS
        grid_file = fs.get(archivo['file_id'])
        file_data = grid_file.read()
        
        if archivo['encriptado']:
            # Desencriptar el archivo
            file_data = cipher_suite.decrypt(file_data)
            new_status = False
            message = 'Archivo desencriptado correctamente'
        else:
            # Encriptar el archivo
            file_data = cipher_suite.encrypt(file_data)
            new_status = True
            message = 'Archivo encriptado correctamente'
        
        # Eliminar el archivo viejo de GridFS
        fs.delete(archivo['file_id'])
        
        # Subir el nuevo archivo (encriptado/desencriptado) a GridFS
        new_file_id = fs.put(BytesIO(file_data), 
                          filename=archivo['nombre'],
                          content_type=archivo['content_type'])
        
        # Actualizar los metadatos en MongoDB (IMPORTANTE: incluir encriptado)
        result = mongo.db.archivos.update_one(
            {'_id': ObjectId(file_id)},
            {'$set': {
                'file_id': new_file_id,
                'encriptado': new_status,  # Este campo debe actualizarse
                'tamaño': len(file_data),
                'fecha_subida': datetime.now()  # Actualizar fecha de modificación
            }}
        )
        
        # Verificar que la actualización fue exitosa
        if result.modified_count == 0:
            raise Exception("No se pudo actualizar el estado en la base de datos")
        
        return jsonify({
            'success': True, 
            'message': message, 
            'encriptado': new_status
        })
    
    except Exception as e:
        app.logger.error(f"Error al cambiar encriptación {file_id}: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'Error al procesar archivo: {str(e)}'
        }), 500

@app.route('/delete/<file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        # Verificar que el archivo pertenece al usuario actual
        archivo = mongo.db.archivos.find_one({
            '_id': ObjectId(file_id),
            'usuario': current_user.username
        })
        
        if not archivo:
            return jsonify({'success': False, 'message': 'Archivo no encontrado'}), 404
        
        # Eliminar el archivo de GridFS
        fs.delete(archivo['file_id'])
        
        # Eliminar el registro de MongoDB
        result = mongo.db.archivos.delete_one({'_id': ObjectId(file_id)})
        
        if result.deleted_count == 1:
            return jsonify({
                'success': True, 
                'message': 'Archivo eliminado correctamente'
            })
        else:
            return jsonify({
                'success': False, 
                'message': 'No se pudo eliminar el archivo'
            }), 500
    
    except Exception as e:
        app.logger.error(f"Error al eliminar archivo {file_id}: {str(e)}")
        return jsonify({
            'success': False, 
            'message': f'Error al eliminar archivo: {str(e)}'
        }), 500

# Rutas de encuestas
@app.route('/survey')
def survey():
    return render_template('survey.html')

@app.route('/re_answer')
@login_required  
def re_answer():
    try:

        encuestas = list(mongo.db.encuestas.find())
        

        datos_encuestas = []
        
        for encuesta in encuestas:
  
            for pregunta in encuesta.get('preguntas', []):
                datos_encuestas.append({
                    'pregunta': pregunta['texto'],
                    'tipo': pregunta['tipo'],
                    'respuesta': pregunta['respuesta'],
                    'fecha': encuesta['fecha_creacion'].strftime('%Y-%m-%d %H:%M') if 'fecha_creacion' in encuesta else 'Sin fecha'
                })
        
        # Agrupar respuestas por pregunta
        preguntas_respuestas = {}
        for dato in datos_encuestas:
            if dato['pregunta'] not in preguntas_respuestas:
                preguntas_respuestas[dato['pregunta']] = []  
            preguntas_respuestas[dato['pregunta']].append({
                'respuesta': dato['respuesta'],
                'fecha': dato['fecha'],
                'tipo': dato['tipo']
            })
        
        return render_template('re_answer.html', preguntas_respuestas=preguntas_respuestas)
    
    except Exception as e:
        print(f"Error al obtener respuestas: {str(e)}")
        flash('Error al cargar las respuestas', 'error')
        return redirect(url_for('admin'))


@app.route('/generate_report')
@login_required
def generate_report():

    pass

@app.route('/generate_pptx_report')
@login_required
def generate_pptx_report():

    pass

@app.route('/generate_xls_report')
@login_required
def generate_xls_report():
   
    pass


@app.route('/submit_survey', methods=['POST'])
@login_required
def submit_survey():
    try:
       
        tiempo_espera = request.form.get('pregunta1', '0')  # Numérico (minutos)
        mejora = request.form.get('pregunta2', 'No especificado')  # Abierta
        calificacion_servicio = request.form.get('pregunta3', '0')  # Escala 1-5
        recomendacion = request.form.get('pregunta4', 'No especificado')  # Opción
        soporte_tecnico = request.form.get('pregunta5', 'No especificado')  # Opción

        # Crear estructura de la encuesta
        encuesta_data = {
            'usuario_id': ObjectId(current_user.id),
            'nombre': 'Encuesta de satisfacción',
            'preguntas': [
                {
                    'texto': '¿Cuál ha sido el tiempo de espera? (en minutos)',
                    'tipo': 'numerico',
                    'respuesta': int(tiempo_espera) if tiempo_espera.isdigit() else 0,
                    'orden': 1
                },
                {
                    'texto': '¿Qué te gustaría mejorar?',
                    'tipo': 'abierta',
                    'respuesta': mejora,
                    'orden': 2
                },
                {
                    'texto': '¿Cómo calificarías nuestro servicio?',
                    'tipo': 'escala',
                    'respuesta': int(calificacion_servicio) if calificacion_servicio.isdigit() else 0,
                    'orden': 3
                },
                {
                    'texto': '¿Recomendarías nuestro servicio?',
                    'tipo': 'opcion',
                    'respuesta': recomendacion,
                    'orden': 4
                },
                {
                    'texto': '¿Cómo calificarías el soporte técnico?',
                    'tipo': 'opcion',
                    'respuesta': soporte_tecnico,
                    'orden': 5
                }
            ],
            'fecha_creacion': datetime.now()
        }

        # Guardar en la base de datos
        mongo.db.encuestas.insert_one(encuesta_data)
        flash('Encuesta enviada correctamente', 'success')
        return redirect(url_for('panel_user'))

    except Exception as e:
        print(f"Error al procesar encuesta: {str(e)}")
        flash('Error al enviar la encuesta', 'error')
        return redirect(url_for('survey'))





if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    if not os.path.exists('reports'):
        os.makedirs('reports')
    app.run(debug=True)