from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, redirect, render_template, session, url_for
from authlib.integrations.flask_client import OAuth
from urllib.parse import quote_plus, urlencode
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from functools import wraps
from jose import jwt
import requests
import constants
import json

app = Flask(__name__)

client = datastore.Client()

# global variables
CLIENT_ID = 'q0P0veZixECakaDBGHCl142uy5JV93CW'
CLIENT_SECRET = 'HpQsXEDiBDnWnlr-5pFFmKuc_qCwRZ54kIC8L97tcxscQ4IsU4Q-e7qL0URmL8yC'
DOMAIN = 'milldevo-portfolio-project.us.auth0.com'
APP_SECRET_KEY = "42e3ed0aee8e1229f41fff36f59e38dc8823deecd0e9fd9390cc15c5d7dd0cc3"
APP_URL = "https://milldevo-final.ue.r.appspot.com/"
ALGORITHMS = ["RS256"]

app.secret_key = APP_SECRET_KEY
oauth = OAuth(app)

# register oauth
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration'
)

# verify jwt exists and is associated with this project resturn 1 if false
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return 1
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return 1
    if unverified_header["alg"] == "HS256":
        return 1
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            return 1
        except jwt.JWTClaimsError:
            return 1
        except Exception:
            return 1
        return payload
    else:
        return 1

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        
# users login or create new profiles
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

# redirection from login
@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return user_post(token)

def user_post(token):
    new_user = datastore.entity.Entity(key=client.key(constants.users))
    new_user.update({"id": token['userinfo']['sub']})
    client.put(new_user)
    return redirect("/")

# logs user out and clears session data
@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": APP_URL,
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )

# home route displays home page
@app.route('/')
def home():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))

# returns all users in json format
@app.route('/users', methods=['GET'])
def users_get():
    if request.method == 'GET':
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        return (json.dumps(results), 200)
    else:
        return ('Method not recogonized', 404)

# /boats supports post and get, must have valid jwt for each
@app.route('/boats', methods=['POST','GET'])
def boat_get_post():
    if 'application/json' not in request.accept_mimetypes:   # must be able to accept json response
        res = {"Error": "Unsupported MIME type requested"}
        return (res, 406)
    if request.method == "POST":
        return boat_post()
    elif request.method == 'GET':
        return boats_get()
    else:
        response = {"Error": "Method not allowed"}
        return (response, 405)
       
# create new boat jwt owner is boat owneer
def boat_post():
    content = request.get_json()
    payload = verify_jwt(request)
    if payload == 1:       # non balid jwt
        return ({"Error": "jwt required to create boat"}, 401)
    if 'type' not in content or 'name' not in content or 'length' not in content:  # all fields must  be filled
        response = {"Error": "length type and name must be provided"}
        return (response, 400)   # all required fields
    if len(content['name']) == 0 or int(content['length']) < 1:   # data supplied must be valid
        response = {"Error": "length type and name must be provided"}
        return (response, 400)
    new_boat = datastore.entity.Entity(key=client.key(constants.boats))
    new_boat.update({"name": content["name"],"loads": [], "type": content["type"],"length": content["length"], "owner": payload["sub"]})
    client.put(new_boat)
    new_boat["self"] = request.base_url + "/" + str(new_boat.key.id)
    client.put(new_boat)
    new_boat["id"] = new_boat.key.id
    return (new_boat, 201)

# return all boats owned by jwt owner with 5 results per page
def boats_get():
    payload = verify_jwt(request)
    if payload == 1:
        return ("jwt required to create boat", 401)
    query = client.query(kind=constants.boats)
    query.add_filter("owner", "=", payload['sub'])
    total = len(list(query.fetch()))
    q_limit = int(request.args.get('limit', '5'))
    q_offset = int(request.args.get('offset', '0'))
    l_iterator = query.fetch(limit= q_limit, offset=q_offset)
    pages = l_iterator.pages
    results = list(next(pages))
    if l_iterator.next_page_token:
        next_offset = q_offset + q_limit
        next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
    else:
        next_url = None
    for boat in results:
        boat["id"] = boat.key.id
    output = {"total boats": total, "boats": results}
    if next_url:
        output["next"] = next_url
    return (json.dumps(output), 200)

# edit delete and get boat must be done by boat owner (jwt)
@app.route('/boats/<id>', methods=['PATCH','DELETE','GET', 'PUT'])
def boats_put_get_patch_delete(id):
    payload = verify_jwt(request)
    if payload == 1:       # must have valid jwt
        return ({"Error": "Jwt required to alter boat"}, 401)
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)
    if boat == None:            # boat does not exist
        response = {"Error": "No boat with this boat_id exists"}
        return (response, 404)
    if boat['owner'] != payload['sub']:      # non owner jwt
        response = {"Error": "Action not allowed, must own boat to perform action"}
        return (response, 401)
    if request.method == 'DELETE':
        return boat_delete(id, boat)
    if 'application/json' not in request.accept_mimetypes:  # response must be json
        response = {"Error": "Unsupported MIME type requested"}   # response sent as json
        return (response, 406)
    if request.method == 'PUT':
       return boat_put(id, boat)
    elif request.method == 'PATCH':
       return boat_patch(id, boat)
    elif request.method == 'GET':
        return boat_get(id, boat)
    else:
        return 'Method not recognized'

# edit boat with put jwt already validated
# name length and type required fields in body
def boat_put(id, boat):
    content = request.get_json()
    if 'type' not in content or 'name' not in content or 'length' not in content:  # all fields must  be filled
        response = {"Error": "length type and name must be provided"}
        return (response, 400)
    if len(content['name']) == 0 or int(content['length']) < 1:   # invalid data sent
        response = {"Error": "length type and name must be provided"}
        return (response, 400)
    boat['name'] = content['name']
    boat['type'] = content['type']
    boat['length'] = content['length']
    client.put(boat)
    boat["id"] = boat.key.id
    return (json.dumps(boat), 200)

# edit boat with patch jwt already validated
# no body fields required
def boat_patch(id, boat):
    content = request.get_json()
    if 'name' in content:
        if len(content['name']) > 0:    # if data sent it must be valid
            boat['name'] = content['name']
        else:
            return ({"Error": "invalid data"}, 400)
    if 'type' in content:
        boat['type'] = content['type']
    if 'length' in content:
        if content['length'] > 0:
            boat['length'] = content['length']
        else:
            return ({"Error": "Invalid data"}, 400)
    client.put(boat)
    boat["id"] = boat.key.id
    return (json.dumps(boat), 200)

# delete boat, owner jwt required loads on boat are now boatless
def boat_delete(id, boat):
    query = client.query(kind=constants.loads)
    results = list(query.fetch())
    loads = boat["loads"]
    for i in range(len(loads)):
        load_key = client.key(constants.loads, int(loads[i]["id"]))
        load = client.get(key=load_key)
        load["carrier"] = None         # update all load['carrier']
        client.put(load)
    client.delete(boat)
    return ('',204)

# return boat by id owner jwt required
def boat_get(id, boat):
    boat["id"] = boat.key.id
    return (json.dumps(boat), 200)

# put load onto a boat, unprotected endpoint
# PUT adds load to boat DELETE removes load from boat
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def boat_gets_load(load_id, boat_id):
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)
    if boat == None or load == None:    # boat or load do not exist
        response = {"Error": "The specified boat and/or load does not exist"}
        return (response, 404)
    if request.method == "PUT":
        return load_put_boat(load, boat, boat_id)
    elif request.method == "DELETE":
        return boat_departs_load(load, boat, boat_id)
    else:
        return ({"Error": "Method not allowed"}, 405)
        
# load added to boat
def load_put_boat(load, boat, boat_id):
    if load["carrier"] != None:      # load already has carrier cannot have multiple
        response = {"Error": "The load is already loaded on another boat"}
        return (response, 403)
    load["carrier"] = {"id": boat.key.id, "name": boat["name"], "self": boat["self"]}
    client.put(load)
    loadInfo = {"id": load.key.id, "self": load["self"]}
    boat['loads'].append(loadInfo)
    client.put(boat)
    return ("", 204)

# load removed from boat
def boat_departs_load(load, boat, boat_id):
    found = False
    for i in range(len(boat["loads"])):
        if boat["loads"][i]["id"] == load.key.id:
            found = True
            break
    if not found:
        response = {"Error": "No boat with this boat_id is loaded with the load with this load_id"}
        return (response, 403)
    load["carrier"] = None
    client.put(load)
    for i in range(len(boat["loads"])):
        if boat["loads"][i]["id"] == load.key.id:
            boat["loads"].pop(i)      # remove load from boat
            client.put(boat)
            break
    return ("", 204)

"""
# get all loads from given boat jwt required
@app.route('/boats/<boat_id>/loads', methods=['GET'])
def boat_get_all_loads(boat_id):
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    if boat == None:
        message = {"Error": "No boat with this boat_id exists"}
        return (message, 404)
    payload = verify_jwt(request)
    if payload == 1:       # must have valid jwt
        return ({"Error": "Jwt required to alter boat"}, 401)
    if boat['owner'] != payload['sub']:      # non owner jwt
        response = {"Error": "Action not allowed, must own boat to perform action"}
        return (response, 401)
    if 'application/json' not in request.accept_mimetypes:  # response must be json
        response = {"Error": "Unsupported MIME type requested"}   # response sent as json
        return (response, 406)
    body = {"loads": []}
    for i in range(len(boat["loads"])):
        load_key = client.key(constants.loads, int(boat["loads"][i]["id"]))
        load = client.get(key=load_key)
        body["loads"].append(load)
    return (body, 200)
"""

# create and get all loads unprotected endpoint
@app.route('/loads', methods=['POST','GET'])
def load_get_post():
    if 'application/json' not in request.accept_mimetypes:  # response must be json
        res = {"Error": "Unsupported MIME type requested"}
        return (res, 406)
    if request.method == 'POST':
        return load_post()
    elif request.method == 'GET':
        return loads_get()
    else:
        response = {"Error": "Method not allowed"}
        return (response, 405)

# create a new load 
# colume item and creation_date required fields
def load_post():
    content = request.get_json()
    new_load = datastore.entity.Entity(key=client.key(constants.loads))
    if 'volume' not in content or 'item' not in content or 'creation_date' not in  content:
        response = {"Error": "required fields missing"}
        return (response, 400)     
    if content['volume'] <= 0 or content['item'] == '':
        response = {"Error": "required fields invalid"}
        return (response, 400)
    new_load.update({"volume": content["volume"],"carrier": None, "item": content["item"], "creation_date": content["creation_date"]})
    client.put(new_load)
    new_load["self"] = request.base_url + "/" + str(new_load.key.id)
    client.put(new_load)
    new_load["id"] = new_load.key.id
    return (new_load, 201)

# get all loads unprotected endpoint
# display 5 results per page
def loads_get():
    query = client.query(kind=constants.loads)
    length = list(query.fetch())
    length = len(length)
    q_limit = int(request.args.get('limit', '5'))
    q_offset = int(request.args.get('offset', '0'))
    l_iterator = query.fetch(limit= q_limit, offset=q_offset)
    pages = l_iterator.pages
    results = list(next(pages))
    if l_iterator.next_page_token:
        next_offset = q_offset + q_limit
        next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
    else:
        next_url = None
    for e in results:
        e["id"] = e.key.id
    output = {"Total": length, "loads": results}
    if next_url:
        output["next"] = next_url
    return (json.dumps(output), 200)

# get edit or delete a load uprotected endpoint
@app.route('/loads/<id>', methods=['DELETE','GET', 'PUT', 'PATCH'])
def loads_delete(id):
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)
    if load == None:
        response = {"Error": "No load with this load_id exists"}
        return (response, 404)
    if request.method == 'DELETE':
        return load_delete(id)
    if 'application/json' not in request.accept_mimetypes:  
        res = {"Error": "unsupported MIME type requested"}
        return (res, 406)     # following methods return json
    elif request.method == 'GET':
        return load_get(id)
    elif request.method == 'PUT':
        return load_put(id)
    elif request.method == 'PATCH':
        return load_patch(id)
    else:
        return ({"Error": "Method not allowed"}, 405)

# delete a load
# remove load from any boat carrying load
def load_delete(id):
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)
    if load["carrier"] != None:
        boat_key = client.key(constants.boats, load["carrier"]["id"])
        boat = client.get(key=boat_key)
        for i in range(len(boat["loads"])):
            if boat.key.id == load["carrier"]["id"]:
                boat["loads"].pop(i)    # remove load from boat
                client.put(boat)
                break
    client.delete(load)
    return ('',204)

# get a load by id
def load_get(id):
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)
    load["id"] = load.key.id
    return (json.dumps(load), 200)

# edit a load with put
# colume creation_date and item required fields
def load_put(id):
    content = request.get_json()
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)
    if 'volume' not in content or 'item' not in content or 'creation_date' not in  content:
        response = {"Error": "required fields missing"}
        return (response, 400)
    if content['volume'] <= 0 or content['item'] == '':
        response = {"Error": "required fields invalid"}
        return (response, 400)
    load.update({"volume": content["volume"],"carrier": None, "item": content["item"], "creation_date": content["creation_date"]})
    client.put(load)
    load["id"] = load.key.id
    return (load, 200)

# edit a boat with patch no required fields
def load_patch(id):
    content = request.get_json()
    load_key = client.key(constants.loads, int(id))
    load = client.get(key=load_key)
    if 'volume' in content:
        if content['volume'] <= 0:
            response = {"Error": "required fields invalid"}
            return (response, 400)
        load['volume'] = content['volume']
    if 'item' in content:
        if content['item'] == '':
            response = {"Error": "required fields invalid"}
            return (response, 400)
        load['item'] = content['item']
    if 'creation_date' in content:
        load['creation_date'] = content['creation_date']
    client.put(load)
    load["id"] = load.key.id
    return (load, 200)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)