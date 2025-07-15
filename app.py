from flask import Flask, render_template, request, redirect, url_for
import sqlite3, os
import contextlib
import joblib
import re
import pandas as pd
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from create_database import setup_database
from werkzeug.utils import secure_filename
from database1 import get_user_by_username, insert_user
from utils import login_required, set_session
from database1 import initialize_database
from database1 import get_user_by_username
from prophet import Prophet
import plotly.graph_objs as go
import plotly.offline as pyo
from flask import (
    Flask, render_template, 
    request, session, redirect
)


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'

database = "users.db"
setup_database(name=database)

app.secret_key = 'xpSm7p5bgJY8rNoBjGWiz5yjxM-NEBlW6SIBI62OkLc='

initialize_database()

# Load and clean dataset
df = pd.read_csv('crop_yield.csv')
df.dropna(subset=['Yield'], inplace=True)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Home
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/dashboard')
def dashboard():
    return render_template('about.html')

@app.route('/view_products')
def view_products():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    conn.close()
    return render_template('view_products.html', products=products)

@app.route('/view_orders')
def view_orders():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT orders.id, orders.customer_name, orders.quantity, orders.mobile, orders.address, products.name
        FROM orders
        JOIN products ON orders.product_id = products.id
    """)
    orders = cursor.fetchall()
    conn.close()
    return render_template('view_orders.html', orders=orders)


@app.route('/delete_order/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Delete the order based on the order_id
    cursor.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    # Redirect to the orders page after deletion
    return redirect(url_for('view_orders'))


from werkzeug.utils import secure_filename

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        price = request.form['price']
        total_units = request.form['units']  # make sure your input name="total_units"
        image = request.files['image']

        # Save the image file securely
        filename = secure_filename(image.filename)
        upload_folder = os.path.join('static', 'uploads')
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        image.save(os.path.join(upload_folder, filename))

        # Save only the filename in the DB (not full path with slashes)
        image_path = filename

        # Save product to database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO products (name, category, price_per_unit, total_units, image) VALUES (?, ?, ?, ?, ?)",
            (name, category, price, total_units, image_path)
        )
        conn.commit()
        conn.close()

        return redirect(url_for('dashboard'))

    # Categories list
    categories = ['Fruits', 'Vegetables', 'Grains', 'Dairy', 'Seeds', 'Plants']
    return render_template('add_product.html', categories=categories)

# Farmer - Edit product
@app.route('/edit_product/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        price = request.form['price']
        units = request.form['units']
        conn.execute('UPDATE products SET name = ?, category = ?, price_per_unit = ?, total_units = ? WHERE id = ?',
                     (name, category, price, units, id))
        conn.commit()
        conn.close()
        return redirect(url_for('view_products'))

    conn.close()
    return render_template('edit_product.html', product=product)

# Farmer - Delete product
@app.route('/delete_product/<int:id>')
def delete_product(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM products WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('view_products'))

# Customer - View products
@app.route('/customer', methods=['GET', 'POST'])
def customer():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Get all distinct categories for the dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = [row[0] for row in cursor.fetchall()]

    selected_category = request.args.get('category')
    if selected_category and selected_category != "All":
        cursor.execute("SELECT * FROM products WHERE category = ?", (selected_category,))
    else:
        cursor.execute("SELECT * FROM products")
    
    products = cursor.fetchall()
    conn.close()

    return render_template("customer.html", products=products, categories=categories, selected_category=selected_category)

@app.route('/seller', methods=['GET', 'POST'])
def seller():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Get all distinct categories for the dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = [row[0] for row in cursor.fetchall()]

    selected_category = request.args.get('category')
    if selected_category and selected_category != "All":
        cursor.execute("SELECT * FROM products WHERE category = ?", (selected_category,))
    else:
        cursor.execute("SELECT * FROM products")
    
    products = cursor.fetchall()
    conn.close()

    return render_template("seller.html", products=products, categories=categories, selected_category=selected_category)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Set data to variables
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Attempt to query associated user data
    query = 'select username, password, email from users where username = :username'

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: 
        return render_template('login.html', error='Username does not exist')

    # Verify password
    try:
        ph = PasswordHasher()
        ph.verify(account[1], password)
    except VerifyMismatchError:
        return render_template('login.html', error='Incorrect password')

    # Check if password hash needs to be updated
    if ph.check_needs_rehash(account[1]):
        query = 'update set password = :password where username = :username'
        params = {'password': ph.hash(password), 'username': account[0]}

        with contextlib.closing(sqlite3.connect(database)) as conn:
            with conn:
                conn.execute(query, params)

    # Set cookie for user session
    set_session(
        username=account[0], 
        email=account[2], 
        remember_me='remember-me' in request.form
    )
    
    return redirect('/customer')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Store data to variables 
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    username = request.form.get('username')
    email = request.form.get('email')

    # Verify data
    if len(password) < 8:
        return render_template('register.html', error='Your password must be 8 or more characters')
    if password != confirm_password:
        return render_template('register.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register.html', error='Username must only be letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register.html', error='Username must be between 4 and 25 characters')

    query = 'select username from users where username = :username;'
    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register.html', error='Username already exists')

    # Create password hash
    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    query = 'insert into users(username, password, email) values (:username, :password, :email);'
    params = {
        'username': username,
        'password': hashed_password,
        'email': email
    }

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, params)

    # We can log the user in right away since no email verification
    set_session( username=username, email=email)
    return redirect('/login')


@app.route('/login2', methods=['GET', 'POST'], endpoint='seller_login')
def seller_login():
    if request.method == 'GET':
        return render_template('login2.html')

    username = request.form.get('username')
    password = request.form.get('password')
    
    query = 'select username, password, email from sellers where username = :username'

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account:
        return render_template('login2.html', error='Username does not exist')

    try:
        ph = PasswordHasher()
        ph.verify(account[1], password)
    except VerifyMismatchError:
        return render_template('login2.html', error='Incorrect password')

    if ph.check_needs_rehash(account[1]):
        query = 'update sellers set password = :password where username = :username'
        params = {'password': ph.hash(password), 'username': account[0]}
        with contextlib.closing(sqlite3.connect(database)) as conn:
            with conn:
                conn.execute(query, params)

    set_session(
        username=account[0],
        email=account[2],
        remember_me='remember-me' in request.form
    )
    return redirect('/seller')


@app.route('/register2', methods=['GET', 'POST'], endpoint='seller_register')
def seller_register():
    if request.method == 'GET':
        return render_template('register2.html')

    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    username = request.form.get('username')
    email = request.form.get('email')

    if len(password) < 8:
        return render_template('register2.html', error='Your password must be 8 or more characters')
    if password != confirm_password:
        return render_template('register2.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register2.html', error='Username must only be letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register2.html', error='Username must be between 4 and 25 characters')

    query = 'select username from sellers where username = :username;'
    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register2.html', error='Username already exists')

    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    query = 'insert into sellers(username, password, email) values (:username, :password, :email);'
    params = {
        'username': username,
        'password': hashed_password,
        'email': email
    }

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, params)

    set_session(username=username, email=email)
    return redirect('/login2')
@app.route('/seller_homepage')
def seller_homepage():
    return render_template('seller_homepage.html')  # Create this template

@app.route('/login1', methods=['GET', 'POST'])
def login1():
    if request.method == 'GET':
        return render_template('login1.html')

    username = request.form.get('username')
    password = request.form.get('password')

    account = get_user_by_username(username)
    if not account:
        return render_template('login1.html', error='Username does not exist')

    try:
        ph = PasswordHasher()
        ph.verify(account[2], password)  # account[2] is the password from DB
    except VerifyMismatchError:
        return render_template('login1.html', error='Incorrect password')

    # Optional: handle rehashing
    if ph.check_needs_rehash(account[2]):
        from database1 import get_connection
        with get_connection() as conn:
            conn.execute('UPDATE users SET password = ? WHERE username = ?', 
                         (ph.hash(password), username))

    set_session(username=account[1], email=account[3], remember_me='remember-me' in request.form)
    return redirect('/transportar')


@app.route('/register1', methods=['GET', 'POST'])
def register1():
    if request.method == 'GET':
        return render_template('register1.html')

    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')

    if len(password) < 8:
        return render_template('register1.html', error='Password must be 8 or more characters')
    if password != confirm_password:
        return render_template('register1.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register1.html', error='Username must contain only letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register1.html', error='Username must be 4–25 characters')

    if get_user_by_username(username):
        return render_template('register1.html', error='Username already exists')

    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    try:
        insert_user(username, hashed_password, email)
    except Exception as e:
        return render_template('register1.html', error='Something went wrong while registering')

    set_session(username=username, email=email)
    return redirect('/login1')


# Customer - Order product
@app.route('/order/<int:product_id>', methods=['GET', 'POST'])
def order(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        quantity = request.form['quantity']
        mobile = request.form['mobile']
        address = request.form['address']

        conn.execute('INSERT INTO orders (product_id, customer_name, quantity, mobile, address) VALUES (?, ?, ?, ?, ?)',
                     (product_id, name, quantity, mobile, address))
        conn.commit()
        conn.close()
        return redirect(url_for('customer'))

    conn.close()
    return render_template('order.html', product=product)

@app.route('/send_to_transportar', methods=['POST'])
def send_to_transportar():
    customer_name = request.form['customer_name']
    mobile = request.form['mobile']
    address = request.form['address']
    product_name = request.form['product_name']
    quantity = request.form['quantity']

    # Insert into transport_orders table
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''INSERT INTO transport_orders (customer_name, mobile, address, product_name, quantity) 
                      VALUES (?, ?, ?, ?, ?)''', 
                   (customer_name, mobile, address, product_name, quantity))
    conn.commit()
    conn.close()

    return redirect('/view_orders')  # Redirect back to the orders page

@app.route('/transportar')
def transportar():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Fetch transport A orders
    cursor.execute('''
        SELECT orders.customer_name, products.name as product, orders.quantity, orders.mobile, orders.address
        FROM orders
        JOIN products ON orders.product_id = products.id
        WHERE orders.transport_name = 'TransportA'
    ''')
    transport_a_orders = cursor.fetchall()

    # Fetch transport B orders
    cursor.execute('''
        SELECT orders.customer_name, products.name as product, orders.quantity, orders.mobile, orders.address
        FROM orders
        JOIN products ON orders.product_id = products.id
        WHERE orders.transport_name = 'TransportB'
    ''')
    transport_b_orders = cursor.fetchall()

    # Fetch transport C orders
    cursor.execute('''
        SELECT orders.customer_name, products.name as product, orders.quantity, orders.mobile, orders.address
        FROM orders
        JOIN products ON orders.product_id = products.id
        WHERE orders.transport_name = 'TransportC'
    ''')
    transport_c_orders = cursor.fetchall()

    conn.close()

    return render_template('transportar.html',
                           transport_a_orders=transport_a_orders,
                           transport_b_orders=transport_b_orders,
                           transport_c_orders=transport_c_orders)


@app.route('/delete_transport_order/<int:order_id>', methods=['POST'])
def delete_transport_order(order_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Delete the order based on the order_id
    cursor.execute("DELETE FROM transport_orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    # Redirect to the transporter orders page after deletion
    return redirect(url_for('transportar'))


@app.route('/demand')
def demand():
    crops = sorted(df['Crop'].unique())
    states = sorted(df['State'].unique())
    return render_template('forecast.html', crops=crops, states=states)

@app.route('/predict', methods=['POST'])
def predict():
    crop = request.form['crop']
    state = request.form['state']

    data = df[(df['Crop'] == crop) & (df['State'] == state)]
    if data.empty:
        return "No data available for selected crop and state."

    data = data[['Crop_Year', 'Yield']].groupby('Crop_Year').mean().reset_index()
    data = data.rename(columns={'Crop_Year': 'ds', 'Yield': 'y'})
    data['ds'] = pd.to_datetime(data['ds'], format='%Y')

    # Train Prophet model
    model = Prophet()
    model.fit(data)

    future = model.make_future_dataframe(periods=5, freq='Y')
    forecast = model.predict(future)

    # Plotting forecast using Plotly
    trace1 = go.Scatter(x=forecast['ds'], y=forecast['yhat'], mode='lines+markers', name='Predicted Yield')
    trace2 = go.Scatter(x=data['ds'], y=data['y'], mode='lines+markers', name='Actual Yield')

    layout = go.Layout(title=f'Yield Forecast for {crop} in {state}', xaxis=dict(title='Year'), yaxis=dict(title='Yield'))
    fig = go.Figure(data=[trace1, trace2], layout=layout)
    graph_html = pyo.plot(fig, output_type='div')

    return render_template('forecast.html', crops=sorted(df['Crop'].unique()), states=sorted(df['State'].unique()), plot_div=graph_html)
@app.route('/assign_transport/<transport_name>/<int:order_id>')
def assign_transport(transport_name, order_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("UPDATE orders SET transport_name = ? WHERE id = ?", (transport_name, order_id))
    conn.commit()
    conn.close()

    return redirect(url_for('view_orders'))

def add_transport_name_column():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE orders ADD COLUMN transport_name TEXT;")
        conn.commit()
    except sqlite3.OperationalError:
        # Column already exists
        pass
    conn.close()

# Call it once when the app starts
add_transport_name_column()

if __name__ == '__main__':
    app.run(debug=True)
