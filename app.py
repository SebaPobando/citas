from flask import Flask, render_template, request, redirect, url_for, flash, make_response, abort, request
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = 'luteamo'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\sebap\\Documents\\Workspace\\citasapp\\database\\database.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('quotes', lazy=True))

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quote_id = db.Column(db.Integer, db.ForeignKey('quote.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quote = db.relationship('Quote', backref=db.backref('favorites', lazy=True))
    user = db.relationship('User', backref=db.backref('favorites', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        re_password = request.form['re_password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('¡Ya se encuentra registrado!', 'error')
            return redirect(url_for('home'))

        if password != re_password:
            flash('Las contraseñas no coinciden. Por favor, inténtalo de nuevo.', 'error')
            return redirect(url_for('home'))
        
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('¡Registro exitoso!', 'success')
        return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('perfil')) 

        flash('Credenciales incorrectas. Por favor, inténtalo de nuevo.', 'error')
        return redirect(url_for('login'))

    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('¡Has cerrado sesión exitosamente!', 'success')
    response = make_response(redirect(url_for('home')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
@nocache
def perfil():
    # Obtener todas las citas
    quotes = Quote.query.all()
    favorites = Favorite.query.filter_by(user_id=current_user.id).all()
    
    if request.method == 'POST':
        author = request.form['author']
        message = request.form['message']
        new_quote = Quote(author=author, message=message, user_id=current_user.id)
        db.session.add(new_quote)
        db.session.commit()
        flash('Cita agregada con éxito!', 'success')
        return redirect(url_for('perfil'))

    # Eliminar las citas que están en favoritos de la lista de citas
    quotes = [quote for quote in quotes if quote not in [fav.quote for fav in favorites]]

    return render_template('perfil.html', quotes=quotes, favorites=favorites)



@app.route('/add_quote', methods=['POST'])
@login_required
def add_quote():
    if request.method == 'POST':
        author = request.form['author']
        message = request.form['message']
        if not validate_quote_data(author, message):
            return redirect(url_for('perfil'))
        
        new_quote = Quote(author=author, message=message, user_id=current_user.id)
        db.session.add(new_quote)
        db.session.commit()
        flash('¡Cita agregada con éxito!', 'success')
        return redirect(url_for('perfil'))

@app.route('/add_to_favorites/<int:quote_id>', methods=['POST'])
@login_required
def add_to_favorites(quote_id):
    quote = Quote.query.get(quote_id)
    if quote:
        try:
            favorite = Favorite(quote_id=quote.id, user_id=current_user.id)
            db.session.add(favorite)
            db.session.commit()
            flash('Cita agregada a favoritos con éxito!', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('La cita ya está en tus favoritos.', 'warning')
    else:
        flash('No se encontró la cita.', 'error')
    return redirect(url_for('perfil'))

@app.route('/remove_from_favorites/<int:favorite_id>', methods=['POST'])
@login_required
def remove_from_favorites(favorite_id):
    favorite = Favorite.query.get(favorite_id)
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        flash('Cita removida de favoritos con éxito!', 'success')
    else:
        flash('No se encontró la cita en favoritos.', 'error')
    return redirect(url_for('perfil'))

@app.route('/edit_quote/<int:quote_id>', methods=['GET', 'POST'])
@login_required
def edit_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    if quote.user_id != current_user.id:
        abort(403)  # 403 Forbidden: El usuario no tiene permiso para editar esta cita
    if request.method == 'POST':
        new_author = request.form['author']
        new_message = request.form['message']
        if not validate_quote_data(new_author, new_message):
            return redirect(url_for('perfil'))
        
        quote.author = new_author
        quote.message = new_message
        
        db.session.commit()
        
        flash('¡La cita ha sido editada con éxito!', 'success')
        return redirect(url_for('perfil'))
    return render_template('editar.html', quote=quote)


@app.route('/delete_quote/<int:quote_id>', methods=['POST'])
@login_required
def delete_quote(quote_id):
    quote = Quote.query.get_or_404(quote_id)
    if quote.user_id != current_user.id:
        abort(403)  # 403 Forbidden: El usuario no tiene permiso para eliminar esta cita

    try:
        # Eliminar todas las entradas relacionadas en la tabla Favorite
        Favorite.query.filter_by(quote_id=quote_id).delete()
        
        # Eliminar la cita de la tabla Quote
        db.session.delete(quote)
        db.session.commit()
        
        flash('La cita ha sido eliminada con éxito!', 'success')
    except NoResultFound:
        flash('La cita que intentas eliminar no existe.', 'error')
    
    return redirect(url_for('perfil'))

@app.route('/user_summary/<int:user_id>')
@login_required
def user_summary(user_id):
    user = User.query.get_or_404(user_id)
    quotes = Quote.query.filter_by(user_id=user_id).all()
    return render_template('user_summary.html', user=user, quotes=quotes)

# Agregar validaciones de longitud para la adición y edición de citas
def validate_quote_data(author, message):
    if len(author) < 3:
        flash('El nombre del autor debe tener al menos 3 caracteres.', 'error')
        return False
    if len(message) < 10:
        flash('El mensaje debe tener al menos 10 caracteres.', 'error')
        return False
    return True

if __name__ == '__main__':
    app.run(debug=True)
