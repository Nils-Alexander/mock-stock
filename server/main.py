#!/usr/bin/env python3
from flask import Flask, abort, request, jsonify, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, decode_token
import urllib
from datetime import date
import stripe
stripe.api_key = 'sk_test_51MqAs0FTsxKlF1MRWC4XmZWBtMoKLfAztjOPUuSrYKhe44iXOsxW1Bpjn7iYB25MaPTYS4lavof1uaNtpZ8L6XWb00R4o2TDcy'
import json
import base64
import os
from email.message import EmailMessage
import ssl
import smtplib
 
#
#   Naming conventions: (https://realpython.com/python-pep8/)
#
#   Function/Method: lowercase, underscores (function, my_function)
#   Class: capital first letter, pascal casing (Model, MyClass)
#   Constant: uppercase, underscores (CONSTANT, MY_CONSTANT)
#

# Initierande av app och moduler
app = Flask(__name__, template_folder='../client/templates', static_folder='../client')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "OQEIROFZMNVZNDVFFJIASE"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Catch-all router till hemsidan
# POTENTIeLLT:  kan behöva lägga upp vissa specifika för de som bör kräva auth token,
#               även om detta kan kontrolleras på klientsidan
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    return render_template("index.html", path=path)

#Avkodar en bild sträng till fil form
def decode_image(image_string, image_name, product_id):
    decoded_image_data = base64.b64decode(image_string)
    output_folder = "../client/resources/product-pictures"
    full_route = os.path.join(output_folder, str(product_id)+image_name)
    with open(full_route, "wb") as f:
        f.write(decoded_image_data)
    
    new_picture = Product_Pictures(product_id=product_id, pictures=full_route)
    db.session.add(new_picture)
    db.session.commit()
    json_response({'Msg': "Image has been uploaded"}, 200)

#/products_by_event/event_id hämtar alla produkter med avseende på ett produkt id
@app.route('/https/products_by_event/<int:event_id>')
def products_by_event(event_id):
    products = Product.query.join(products_tags).join(Tag).filter(Tag.event_id == event_id).all()
    return jsonify([product.seralize() for product in products])

#/events hämtar och skapar ett event, method: GET, POST
@app.route('/https/events', methods=['GET', 'POST'])
def events():
    if request.method == 'GET':
        events = Event.query.all()
        serialized_events = [event.seralize() for event in events]
        return jsonify(serialized_events)
    
    if request.method == 'POST':
        response = request.get_json()
        event = Event(image=response['image'], text1=response['text1'], text2=response['text2'])
        db.session.add(event)
        db.session.commit()
        serialized_event = event.seralize()
        return jsonify(serialized_event)

#/events/event_id> hämtar ändrar och tar bort ett specifikt event, method: GET, PUT, DELETE
@app.route('/https/events/<int:event_id>', methods=['GET', 'PUT', 'DELETE'])
def event(event_id):
    event = db.session.get(Event, event_id)
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    if request.method == 'GET':
        serialized_event = event.seralize()
        return jsonify(serialized_event)
    if request.method == 'PUT':
        data = request.get_json()
        if data['image'] != None:
            event.image = data['image']
        if data['text1'] != None:
            event.text1 = data['text1']
        if data['text2'] != None:
            event.text2 = data['text2']
        db.session.commit()
        serialized_event = event.serialize()
        return jsonify(serialized_event)
    if request.method == 'DELETE':
        db.session.delete(event)
        db.session.commit()
        return jsonify({'success': True})

#/products/filter hämtar alla produkter efter en lista av filter, method: PUT
@app.route('/https/products/filter', methods = ['PUT'])
def  filter():
    if request.method == 'PUT':
        filter_criteria = request.get_json()
        tag_names = filter_criteria.get('tags')

        # TODO: When 'is_approved' is used, filter to show only approved products
        #products = db.session.query(Product).filter(Product.is_approved == True)
        #return jsonify([p.seralize() for p in products])

        if filter_criteria.get('sort') == 'popularity':
            products = Product.query.join(Product.tags).filter(func.lower(Tag.name).in_([tag.lower() for tag in tag_names])).order_by(Product.views.desc())
            if not tag_names:
                products = db.session.query(Product).order_by(Product.views.desc())

        elif filter_criteria.get('sort') == 'price ascending':
            products = Product.query.join(Product.tags).filter(func.lower(Tag.name).in_([tag.lower() for tag in tag_names])).order_by(Product.price.asc())
            if not tag_names:
                products = db.session.query(Product).order_by(Product.price.asc())

        elif filter_criteria.get('sort') == 'price descending':
            products = Product.query.join(Product.tags).filter(func.lower(Tag.name).in_([tag.lower() for tag in tag_names])).order_by(Product.price.desc())
            if not tag_names:
                products = db.session.query(Product).order_by(Product.price.desc())
            
        elif filter_criteria.get('sort') == 'title ascending':
            products = Product.query.join(Product.tags).filter(func.lower(Tag.name).in_([tag.lower() for tag in tag_names])).order_by(Product.title.asc())
            if not tag_names:
                products = db.session.query(Product).order_by(Product.title.asc())
            
        elif filter_criteria.get('sort') == 'title descending':
            products = Product.query.join(Product.tags).filter(func.lower(Tag.name).in_([tag.lower() for tag in tag_names])).order_by(Product.title.desc())
            if not tag_names:
                products = db.session.query(Product).order_by(Product.title.desc())
            
        elif filter_criteria.get('sort') == 'date ascending':
            products = Product.query.join(Product.tags).filter(func.lower(Tag.name).in_([tag.lower() for tag in tag_names])).order_by(Product.id.asc())
            if not tag_names:
                products = db.session.query(Product).order_by(Product.id.asc())
            
        elif filter_criteria.get('sort') == 'date descending':
            products = Product.query.join(Product.tags).filter(func.lower(Tag.name).in_([tag.lower() for tag in tag_names])).order_by(Product.id.desc())
            if not tag_names:
                products = db.session.query(Product).order_by(Product.id.desc())
            
        if filter_criteria:
            if filter_criteria.get('size'):
                if isinstance(filter_criteria['size'], list):
                    products = products.filter(Product.size.in_(filter_criteria['size']))
                else:
                    products = products.filter_by(size =filter_criteria['size'])
            if filter_criteria.get('price'):
                products = products.filter(Product.price.between(filter_criteria['price'][0], filter_criteria['price'][1]))
            products = products.filter(Product.buyer_id == None)
            products = products.order_by(Product.views.desc()) # TODO Kolla om det funkar att sortera efter views
            return jsonify([p.seralize() for p in products])
        else:
            return jsonify([p.seralize() for p in products])

#/tags skapar en tag, method: POST
@app.route('/https/tags', methods=['POST'])
#@jwt_required()
def tags():
    response = request.get_json()
    if request.method == 'POST':
        if response['name'] == None:
            return json_response({"Msg" : "Tag name cannot be null."})
        else:
            new_tag = Tag(name = func.lower(response['name']), event_id = response['event_id'])
            db.session.add(new_tag)
            db.session.commit()
            return json_response({})

#/tag/tag_id redigerar eller tar bort en specifik tag, method: PUT, DELETE
@app.route('/https/tag/<int:tag_id>', methods=['PUT', 'DELETE'])
#@jwt_required()
def tag(tag_id):
    response = request.get_json()
    if request.method == 'PUT':
        changed_tag = db.session.query(Tag).filter_by(id = tag_id).first()
        if response['name'] != None:
            changed_tag.name = response['name']
        if response['event_id'] != None:
            changed_tag.event_id = response['event_id']
        db.session.commit()
        return jsonify(changed_tag.seralize())
    elif request.method == 'DELETE':
        db.session.delete(Tag.get_or_404(tag_id))
        db.session.commit()
        return json_response({"msg" : "Deleted tag" + tag_id})
    
#/tag-product skapar och tar bort en tag, mehtods: POST, DELETE
@app.route('/https/tag-product', methods=['POST', 'DELETE'])
#@jwt_required()
def tag_product():
    response = request.get_json()
    if request.method == 'POST':
        tag = db.session.query(Tag).filter(func.lower(Tag.name) == response['name'].lower()).first()
        if not tag:
            if response['name'] == None:
                return json_response({"Msg" : "Tag name cannot be null."})
            elif response['event_id'] != None:
                new_tag = Tag(name = response['name'].lower(), event_id = response['event_id'])
                db.session.add(new_tag)
                tag = new_tag
            else:
                new_tag = Tag(name = response['name'].lower(), event_id = response['event_id'])
                db.session.add(new_tag)
                db.session.commit()
                tag = new_tag
        product = db.session.query(Product).filter_by(id=response['product_id']).first()
        product.tags.append(tag)
        db.session.commit()
        return json_response({})

    elif request.method == 'DELETE':
        tag = db.session.query(Tag).filter_by(name=response['name']).first()
        if not tag:
            return json_response({"msg" : "No tag with name" + response['name']})
        product = db.session.query(Product).filter_by(id=response['product_id']).first()
        product.tags.remove(tag)
        db.session.commit()
        return json_response({})

    elif request.method == 'DELETE':
        tag = db.session.query(Tag).filter_by(name=response['name']).first()
        if not tag:
            return json_response({"msg" : "No tag with name" + response['name']})
        product = db.session.query(Product).filter_by(id=response['product_id']).first()
        product.tags.remove(tag)
        db.session.commit()
        return json_response({})

#/get-tags hämtar alla taggar relterade till en produkt, methods: PUT
@app.route('/https/get-tags', methods=['PUT'])
#@jwt_required()
def get_product():
    response = request.get_json()
    if request.method == 'PUT':
        tags = Tag.query.join(Tag.products).filter_by(id = response['product_id'])
        return jsonify([t.seralize() for t in tags])



# Används för json-svar till användare
# payload: json-svaret
# code: svarskoden (e.g. 404, 200)
def json_response(payload, code=200):
    return jsonify(payload), code

#
#
#   Kontorelaterade endpoints

# /users hämtar alla användare och skapar en methods: GET, POST
@app.route('/https/users', methods=['GET', 'POST'])
#@jwt_required()
def users_endpoint():
    response = request.get_json()
    user = User.query.filter_by(email=response['email']).first()
    if request.method == 'GET':
        return json_response({})
    elif request.method == 'POST':
        new_user = User(first_name=response['first_name'],last_name=response['last_name'], email=response['email'], postnr=response['postnr'], telnr=response['telnr'])
        new_user.set_password(response['password'])
        if user:
            return jsonify({'success': False, 'message': 'Email already in use.'})
        else:
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'success': True, 'message': 'User created successfully.', "user" : new_user.seralize()})
   


#Logga in
@app.route('/https/login', methods=['POST'])
def login_endpoint():
    if request.method == 'POST':
        x = User.query.filter_by(email=request.get_json()['login_email']).first()
        if x:
            password_hash= request.get_json()['login_password']
            if bcrypt.check_password_hash(x.password_hash, password_hash):
                access_token = create_access_token(identity = x.seralize())
                dict = {"token": access_token, "user": x.seralize()}
                return jsonify({'success': True,'userInfo' : dict})
        return  jsonify({'success': False, 'message': 'Wrong username or password.'})



# Produkt sida hämtar alla produktet (möjligen sortera redan i backend) method:GET
@app.route('/https/products', methods=['GET', 'POST'])
def products():
    if request.method == 'GET':
        product_list = Product.query.all()
        query_list = []
        for product in product_list:
            query_list.append(product.seralize())
        return jsonify(query_list)   
    elif request.method == 'POST':
        response = request.get_json()
        bearer_token = request.headers.get('auth')
        decoded_token = decode_token(bearer_token)
        user_id = decoded_token['sub']['id']
        new_product = Product(title = response['title'], description = response['description'], size = response['size'],views=0, price = response['price'], date = str(date.today()), seller_id = user_id)
        db.session.add(new_product)
        db.session.commit()
        if 'picture_JSON' in response:
            for image_data in response['picture_JSON']:
                image_name = image_data['name']
                image_content = image_data['image']
                decode_image(image_content, image_name, new_product.id)
        return jsonify(new_product.seralize())
       
    
# Produkt/Produkt-id hämta en produkt method:GET
@app.route('/https/products/<int:product_id>', methods=['GET', 'PUT', 'DELETE'])
def products_id(product_id):
    relevant_product = db.session.get(Product, product_id)
    
    if relevant_product == None:
        abort(404)
    if request.method == 'GET':
        relevant_product.views += 1
        db.session.commit()
        if request.headers.get('Authorization') != "":
            bearer_token = request.headers.get('Authorization')
            decoded_token = decode_token(bearer_token)
            is_admin = decoded_token['sub']['is_admin']
        else:
            is_admin = False
        return jsonify(product= relevant_product.seralize_all(), is_admin= is_admin)
    elif request.method == 'PUT':
        response = request.get_json()
        relevant_product.views += 1
        if response['title'] != None:
            relevant_product.title = response['title']
        if response['size'] != None:
            relevant_product.size = response['size']
        if response['description'] != None:
            relevant_product.description = response['description']
        if response['price'] != None:
            relevant_product.price = response['price']
        if response['is_approved'] != None:
            relevant_product.is_approved = response['is_approved']
        if 'picture_JSON' in response:
            if response['picture_JSON'] != None:
                for image_data in response['picture_JSON']:
                    image_name = image_data['name']
                    image_content = image_data['image']
                    decode_image(image_content, image_name, relevant_product.id)
        relevant_product.buyer_id = None
        db.session.commit()
        return(relevant_product.seralize())
    elif request.method == 'DELETE':
        del_pics = Product_Pictures.query.filter(Product_Pictures.product_id == product_id).all()
        for del_pic in del_pics:
            db.session.delete(del_pic)
        prod_del = db.session.get(Product, product_id)
        db.session.delete(prod_del)   
        db.session.commit()
        return json_response({})
    
# Dina-Produkter hämtar alla produkter som en användare har gjort method:GET
@app.route('/https/my-products', methods=['GET'])
#@jwt_required()
def your_products():
    if request.method == 'GET':
        bearer_token = request.headers.get('auth')
        decoded_token = decode_token(bearer_token)
        user_id = decoded_token['sub']['id']
        #Ny metod för att hämta: product_list = Product.query.filter(seller_id = user_id).all
        product_list = Product.query.filter(Product.seller_id == user_id).all()
       # product_list = Product.filter_by(seller_id = user_id).all()
        if product_list == None:
            abort(404)
        seralized_product = []
        for product in product_list:
            seralized_product.append(product.seralize())
        return jsonify(seralized_product)

# My-sales hämtar alla försäljningar en användare har gjort, method: GET
@app.route('/https/my-sales', methods=['GET'])
#@jwt_required()
def your_sales():
    if request.method == 'GET':
        bearer_token = request.headers.get('auth')
        decoded_token = decode_token(bearer_token)
        user_id = decoded_token['sub']['id']
        #Ny metod för att hämta: product_list = Product.query.filter(seller_id = user_id).all
        product_list = Product.query.filter(Product.seller_id == user_id, Product.buyer_id != None).all()
       # product_list = Product.filter_by(seller_id = user_id).all()
        if product_list == None:
            abort(404)
        seralized_product = []
        for product in product_list:
            seralized_product.append(product.seralize())
        return jsonify(seralized_product)

# My-purchases hämtar alla köp en användare har gjort, method: GET
@app.route('/https/my-purchases', methods=['GET'])
#@jwt_required()
def your_purchasess():
    if request.method == 'GET':
        bearer_token = request.headers.get('auth')
        decoded_token = decode_token(bearer_token)
        user_id = decoded_token['sub']['id']
        #Ny metod för att hämta: product_list = Product.query.filter(seller_id = user_id).all
        product_list = Product.query.filter(Product.buyer_id == user_id).all()
       # product_list = Product.filter_by(seller_id = user_id).all()
        if product_list == None:
            abort(404)
        seralized_product = []
        for product in product_list:
            seralized_product.append(product.seralize())
        return jsonify(seralized_product)
       

# Dina-produkter/dina-produkter-id ge info om just en annons som användaren har lagt upp method:GET PUT DELETE
@app.route('/https/my-products/<int:user_id>/<int:product_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def your_product(product_id, user_id):
    response = request.get_json()
    bearer_token = request.headers.get('auth')
    decoded_token = decode_token(bearer_token)
    email = decoded_token['sub']['email']
    user = User.query.filter(User.id == user_id).first()
    if email == user.email or user.is_admin == True:
            requested_product = Product.query.filter(Product.seller_id == user_id, Product.id == product_id).first()
    else:
        requested_product = None
    if requested_product == None:
        abort(404)
    if request.method == 'GET':
        return jsonify(requested_product.seralize())
    elif request.method == 'PUT':
        if response['title'] != None:
            requested_product.title = response['title']
        if response['size'] != None:
            requested_product.size = response['size']
        if response['description'] != None:
            requested_product.description = response['description']
        if response['price'] != None:
            requested_product.price = response['price']
        db.session.commit()
        return(requested_product.seralize())
    elif request.method == 'DELETE':
        db.session.delete(requested_product)
        db.session.commit()
        del_pics = Product_Pictures.query.filter(Product_Pictures.product_id == product_id).all()
        db.session.delete(del_pics)
        db.session.commit()
        return(requested_product.seralize())

# Mina-sidor visa information om användare, köp och annonser method:GET
@app.route('/https/my-page', methods=['GET', 'PUT'])
#@jwt_required
def profile():
    bearer_token = request.headers.get('auth')
    if bearer_token != None:
        decoded_token = decode_token(bearer_token)
        user_id = decoded_token['sub']['id']
        relevant_user = User.query.filter(User.id == user_id).first()
    else:
        relevant_user = None
    #relevant_user = db.session.get(User, response['user_id'])
    if relevant_user == None:
        abort(404)
    if request.method == 'GET':
        return jsonify(relevant_user.seralize_full())
    elif request.method == 'PUT':
        response = request.get_json()
        if response.get('first_name') != None:
            relevant_user.first_name = response['first_name']
        if response.get('last_name') != None:
            relevant_user.last_name = response['last_name']
        if response.get('email') != None:
            relevant_user.email = response['email']
        if response.get('postnr') != None:
            relevant_user.postnr = response['postnr']
        if response.get('telnr') != None:
            relevant_user.telnr = response['telnr']
        if response.get('is_admin') != None:
            relevant_user.is_admin = response['is_admin']
        if response.get('password') != None:
            relevant_user.set_password(response['password']) 
        db.session.commit()
    return jsonify(relevant_user.seralize_full())

# /create-payment-intent skapar en paymentIntent via stripe, method: POST
@app.route('/create-payment-intent', methods=['POST'])
def create_payment_intent():
    response = request.get_json()
    line_items = response.get('lineItems', [])
    
    if not line_items:
        return jsonify({'error': 'Line items cannot be empty.'}), 400

    try:
        intent = stripe.PaymentIntent.create(
            amount=response['amount'],
            currency='SEK',
        )
        return jsonify({'client_secret': intent.client_secret, 'id': intent.id})
    except stripe.error.StripeError as e:
        return jsonify({'error': str(e)}), 500

# /create-checkout-session Skapar en checkout session för stripe, method: POST
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    response = request.get_json()
    line_items = response.get('lineItems', [])
    bearer_token = request.headers.get('auth')
    amount = 0

    for item in line_items:
        item['quantity'] = 1
        amount += item['price_data']['unit_amount'] / 100
    
    if not line_items:
        return jsonify({'error': 'Line items cannot be empty.'}), 400
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            billing_address_collection='required',
            mode='payment',
            success_url=DOMAIN + '/https/receipts/?session_id={CHECKOUT_SESSION_ID}&line_items=' + urllib.parse.quote(json.dumps(line_items)) + '&bearer_token='+bearer_token,
            metadata={
                'amount' : amount,
                #'bearer_token' : bearer_token
            },
            cancel_url=DOMAIN + '/kundkorg',
        )
        return jsonify({'sessionId': session['id']})
    except stripe.error.StripeError as e:
        return jsonify({'error': str(e)}), 500
    
#/receipts hämtar alla kvitton för en användare method: GET
@app.route('/https/receipts/', methods=['GET'])
def reciept():
    session_id = request.args.get('session_id')
    line_items_json = request.args.get('line_items')
    bearer_token = request.args.get('bearer_token')
    line_items = json.loads(line_items_json)
    products = []
    payer_id = 0
    if request.method == 'GET':
        try:
            session = stripe.checkout.Session.retrieve(session_id)
        except stripe.error.InvalidRequestError:
            return jsonify({'error': 'Invalid session ID.'}), 400
        payment_intent_id = stripe.PaymentIntent.retrieve(session.payment_intent).id
        existing_payment = Payment.query.filter(Payment.payment_id == payment_intent_id).first()
        if not existing_payment:
            if (bearer_token):
                decoded_token = decode_token(bearer_token)
                if(decoded_token):
                    payer_id = decoded_token['sub']['id']
            amount = session.metadata['amount']
            payment_intent_id = stripe.PaymentIntent.retrieve(session.payment_intent).id
            new_payment = Payment(amount=amount, payment_id=payment_intent_id, payer_id=payer_id)
            db.session.add(new_payment)
            db.session.commit()
            for item in line_items:
                product_id = item['price_data']['product_data']['metadata']['product_id']
                relevant_product = db.session.get(Product, product_id)
                relevant_product.buyer_id = payer_id
                db.session.commit()
                products.append(relevant_product)
            customer_email = session['customer_details'].email
            order_confirmation(customer_email, products, payment_intent_id)
            return redirect('/kvitto')
        else:
            return redirect('/')
    
products_tags = db.Table('products_tags',
    db.Column('product_id', db.Integer, db.ForeignKey('product.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

#/delete-product-pictures/product_id Tar bort bilder som användaren har lagt till på sin annons, method: DELETE
@app.route('/https/delete-product-pictures/<int:product_id>', methods=['DELETE'])
def delete_pictures(product_id):
    data = request.get_json()
    print(data)
    if request.method == 'DELETE':
        picture = Product_Pictures.query.filter(Product_Pictures.pictures == data['path']).first()
        print(picture)
        db.session.delete(picture)
        db.session.commit()
        return json_response({'Msg': "Picture deleted"}, 200)

# Skickar alla bilder som är kopplade till ett produkt id.
def seralize_all_pictures(product_id):
    if request.method == 'GET':
        pics = Product_Pictures.query.filter(Product_Pictures.product_id == product_id).all()
        prod_pic = []
        for pic in pics:
           prod_pic.append(pic.seralize_filepath())
    return prod_pic

# Skickar iväg ett mail till en köpare.
def sendEmail(email_sender, email_receiver, subject, body):
    email_password = 'djpvxnonisocmkwh'

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())

# Skapar och skickar en orderbekräftelse 
def order_confirmation(buyerEmail, products, payment_intent_id):
    payment = Payment.query.filter_by(payment_id = payment_intent_id).first()
    subject = 'Orderbekräftelse ' + '#00' + str(payment.id)
    sold_items = ''

    for product in products:
        email_to_seller (product)
        sold_items += '\n\t' +str(product.seralize_seller()) + '\n' 

    body = f"""
    Tack så mycket för ditt köp! 

    {sold_items}
    Nästa steg för dig är att kontakta säljaren och komma överens om tid för överlämning av varan. 
    Efter att varan överlämnats och du säkerställt att den är i förväntat skick är det fritt fram för dig att använda den!
    Ifall den inte är i förväntat skick är det bara att kontakta oss på utkladnad.nu.email@gmail.com så hjälper vi dig att lösa problemet.

    Med vänliga hälsningar,
    Dina vänner på Utklädnad.nu
    """
    sendEmail('utkladnad.nu.email@gmail.com', buyerEmail, subject, body)

# Skickar ett mail till säljaren.
def email_to_seller (product):
    seller = User.query.filter_by(id = product.seller_id).first()
    seller_email = seller.email
    subject = 'Såld vara ' + product.title
    body = f"""
    Din vara har blivit såld!

    Någon har köpt din vara {product.title} och kommer snart kontakta dig. När köparen bekräftat att hen fått varan kommer vi genomföra betalningen till dig.
    
    Tack för ditt förtroende!

    Med vänliga hälsningar,
    Dina vänner på Utklädnad.nu
    """
    sendEmail('utkladnad.nu.email@gmail.com', seller_email, subject, body)

#/customerservice skapar ett mail som skickar till vår epost adress, method: POST
@app.route('/https/customerservice', methods=['POST'])
def customerservice():
    email_sender = 'utkladnad.nu.email@gmail.com'
    email_receiver = 'utkladnad.nu.email@gmail.com'

    data = request.get_json()
    first_name = data['firstName']
    last_name = data['lastName']
    email = data['email']
    message = data['message']

    subject = 'Kundtjänst - Kontakt från ' + first_name + ' ' + last_name + ' med email: ' + email
    body = message

    sendEmail(email_sender, email_receiver, subject, body)

    return 'Email sent'

# Skickar tillbaka en bild kopplad till produkten
def seralize_one_pic(id):
    pic = Product_Pictures.query.filter(Product_Pictures.product_id==id).first()
    temp_pic = pic.seralize_filepath()
    return temp_pic

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)    
    last_name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    postnr = db.Column(db.Integer, nullable=False)
    telnr = db.Column(db.Integer,nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    sold_products = db.relationship('Product', backref='seller_user', lazy = True, foreign_keys = 'Product.seller_id')
    bought_products = db.relationship('Product', backref='buyer_user', lazy = True, foreign_keys = 'Product.buyer_id')
    payments = db.relationship('Payment', backref='payer', lazy = True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf8')

    def __repr__(self):
        return '<User {}: {} {}'.format(self.id, self.first_name, self.last_name, self.email)
    
    def seralize_full(self):
        return dict(id=self.id, first_name=self.first_name, last_name=self.last_name, email=self.email, postnr=self.postnr, telnr=self.telnr, is_admin=self.is_admin)

    def seralize(self):
        return dict(id=self.id, first_name=self.first_name, last_name=self.last_name, email=self.email, is_admin=self.is_admin)
    
    def seralize_seller(self):
        return (self.first_name + ' ' + self.last_name + '\n\t' + 'Email: ' + self.email + '\n\t' + 'Mobil: ' + '0'+str(self.telnr) + '\n\t' + 'Postnummer: ' + str(self.postnr))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    size = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    views = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String, nullable=False)
    is_approved = db.Column(db.Boolean, nullable=False, default=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payment.id'), nullable = True)
    tags = db.relationship('Tag', secondary = products_tags, back_populates = 'products')

    def __repr__(self):
        return '<Product {}: {} {} {}>'.format(self.id, self.title, self.size, self.description, self.price, self.seller_id)

    def seralize(self):
        if self.buyer_id == None and self.seller_id == None:
            return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_one_pic(self.id), seller_id=None, buyer_id=None, is_approved=self.is_approved)
        elif self.seller_id == None:
           return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_one_pic(self.id), buyer=self.buyer_user.seralize(), is_approved=self.is_approved)
        elif self.buyer_id == None:
           return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_one_pic(self.id), seller=self.seller_user.seralize_full(), is_approved=self.is_approved)
        else:
            if self.buyer_id == 0:
                return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_one_pic(self.id), seller=self.seller_user.seralize_full(), buyer=0, is_approved=self.is_approved)
            else:
                return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_one_pic(self.id), seller=self.seller_user.seralize_full(), buyer=self.buyer_user.seralize(), is_approved=self.is_approved)

    def seralize_all(self):
        if self.buyer_id == None and self.seller_id == None:
            return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_all_pictures(self.id), seller_id=None, buyer_id=None, is_approved=self.is_approved)
        elif self.seller_id == None:
           return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_all_pictures(self.id), buyer=self.buyer_user.seralize(), is_approved=self.is_approved)
        elif self.buyer_id == None:
           return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_all_pictures(self.id), seller=self.seller_user.seralize_full(), is_approved=self.is_approved)
        else:
            if self.buyer_id == 0:
                return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_all_pictures(self.id), seller=self.seller_user.seralize_full(), buyer=0, is_approved=self.is_approved)
            else:
                return dict(id=self.id, title=self.title, size=self.size, description=self.description, price=self.price, picture = seralize_all_pictures(self.id), seller=self.seller_user.seralize(), buyer=self.buyer_user.seralize(), is_approved=self.is_approved)
    def seralize_seller(self):
        return ('Produkt: ' + str(self.title)+ '\n\t' + ' Säljare: ' + str(self.seller_user.seralize_seller()))

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    products = db.relationship('Product', secondary = products_tags, back_populates='tags')
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=True)

    def seralize(self):
        return dict(id=self.id, name=self.name, event_id=self.event_id)
    
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String, nullable=False)
    text1 = db.Column(db.String, nullable=True)
    text2 = db.Column(db.String, nullable=True)
    tags = db.relationship('Tag', backref='event', lazy=True)

    def seralize(self):
        return dict(id=self.id, image=self.image, text1=self.text1, text2=self.text2)
    
class Product_Pictures(db.Model):
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable = False)
    pictures = db.Column(db.String, primary_key=True, nullable= False)
    
    def seralize(self):
        return dict(product_id = self.products_id, pictures=self.pictures)
    
    def seralize_filepath(self):
        return dict(pictures=self.pictures)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False)
    payment_id = db.Column(db.String, nullable=False)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = True)
   #payer = db.relationship("User", back_populates= "payments")

    def __repr__(self):
        return '<Payment {}: {} {} {}'.format(self.id, self.amount, self.payment_id, self.payer)

    def seralize_without_user(self):
        return dict(id=self.id, amount=self.amount, payment_id=self.payment_id)

    def seralize(self):
        return dict(id=self.id, amount=self.amount, payment_id=self.payment_id, payer=self.payer.seralize())
    


DOMAIN = 'http://localhost:5000' #HA RÄTT DOMAIN, SAMMA SOM NEDAN

if __name__ == "__main__":
    app.run(port=5000, debug=True) # På MacOS, byt till 5001 eller dylikt
    
