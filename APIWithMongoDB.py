from flask import Flask, request, jsonify
from flask_mongoengine import MongoEngine
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'db': 'ecommerce_db',
    'host': 'mongodb+srv://chatapp2022:tfZF3QXP1k0XAuEV@cluster0.g9lcn.mongodb.net/'  # Change the connection string accordingly
}
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this in production
db = MongoEngine(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User model
class User(db.Document):
    username = db.StringField(max_length=20, unique=True, required=True)
    password = db.StringField(required=True)

# Item model
class Item(db.Document):
    name = db.StringField(max_length=100, required=True)
    price = db.FloatField(required=True)

# Routes

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    new_user.save()
    return jsonify({'message': 'User registered successfully'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.objects(username=data['username']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Item creation endpoint
@app.route('/items', methods=['POST'])
@jwt_required()
def create_item():
    data = request.get_json()
    new_item = Item(name=data['name'], price=data['price'])
    new_item.save()
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

if __name__ == '__main__':
    app.run(debug=True)
