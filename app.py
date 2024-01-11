from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this in production
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Item model
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

# Routes

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Item creation endpoint
@app.route('/items', methods=['POST'])
@jwt_required()
def create_item():
    data = request.get_json()
    new_item = Item(name=data['name'], price=data['price'])
    db.session.add(new_item)
    db.session.commit()
    return jsonify({'message': 'Item created successfully'}), 201

# Shopping cart endpoint (example: saving items to the cart)
@app.route('/cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    user_id = get_jwt_identity()
    # Here you would implement logic to save items to the user's shopping cart
    # For simplicity, let's assume the item IDs are provided in the request
    data = request.get_json()
    item_ids = data.get('item_ids', [])
    # Implement your cart logic here
    return jsonify({'message': 'Items added to the cart successfully'}), 200


# Root route
@app.route('/')
def home():
    return jsonify({'message': 'Welcome to the Flask eCommerce API!'})



if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
