from flask import Flask, request, json
from flask_restful import reqparse, abort, Api, Resource
from flask_cors import CORS
# from Crypto.Cipher import AES
# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
# from base64 import b64decode
import paho.mqtt.publish as publish
import paho.mqtt.client as mqtt
import os.path
import datetime
import jwt


app = Flask(__name__)
CORS(app)
api = Api(app)

mongoDB = []

def AES_encryption(secret_key, plain_text):
    # Encryption then return base64 format, key=16 char 
    from Crypto.Cipher import AES
    from base64 import b64encode
    import hashlib
    key16byte = hashlib.md5(secret_key).digest()
    encryption_suite = AES.new(key16byte, AES.MODE_CFB , 'This is an IV456')
    cipher_text = encryption_suite.encrypt(plain_text)
    return b64encode(cipher_text)

def AES_decryption(secret_key, cipher_text):
    # input base64 forma Decryption, key=16 char 
    from Crypto.Cipher import AES
    from base64 import b64decode
    import hashlib
    key16byte = hashlib.md5(secret_key).digest()
    decryption_suite = AES.new(key16byte, AES.MODE_CFB , 'This is an IV456')
    plain_text = decryption_suite.decrypt(b64decode(cipher_text))
    return plain_text

def generate_RSA(uuid):
    '''
    https://gist.github.com/lkdocs/6519378
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    uuid 20byte
    '''
    from Crypto.PublicKey import RSA
    new_key = RSA.generate(bits=1024, e=65537) 
    public_key = new_key.publickey().exportKey("PEM") 
    f = open("keys/"+uuid+"_public.pem", 'wb')
    f.write(public_key)
    f.close()
    private_key = new_key.exportKey("PEM") 
    f = open("keys/"+uuid+"_private.pem", 'wb')
    f.write(private_key)
    f.close()
    return uuid

def encrypt_RSA(message, uuid):
    '''
    https://gist.github.com/lkdocs/6519270
    param: public_key_loc Path to public key
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from base64 import b64encode
    key = open("keys/"+uuid+"_public.pem", "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    
    package = b64encode(encrypted)
    file_name = package[:20]
    f = open("keys/"+file_name+"_secret.enc", 'wb')
    f.write(package)
    f.close()
    return file_name

def decrypt_RSA(file_name, uuid):
    '''
    https://docs.launchkey.com/developer/encryption/python/python-encryption.html
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from base64 import b64decode
    key = open("keys/"+uuid+"_private.pem", "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    package = open("keys/"+file_name+"_secret.enc", "r").read()
    decrypted = rsakey.decrypt(b64decode(package))
    return decrypted


# easy_install http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win-amd64-py2.7.exe

def issue_JWT(transaction):
    """
    transaction event then get startime and duration to set exp
    secret by different consumer
    """
    secret = transaction['secret']
    timestamp = transaction['end']/1000

    jwt_payload = jwt.encode({
        'transaction': transaction,
        'exp': timestamp
    }, secret)
    return jwt_payload
 
def verify_JWT(jwt_payload):
    """
    secret by different consumer
    """    
    try:
        transaction = jwt.decode(jwt_payload, verify=False)
        secret = transaction['transaction']['secret']
        return jwt.decode(jwt_payload, secret)        
    except jwt.ExpiredSignatureError:
        # Signature has expired
        return False

# AES class
class AES(Resource):    

    def get(self):    
        # http://127.0.0.1:5000/aes?secret_key=secret_key&plain_text=plain_text
        # input secret then return AES
        # AES_encryption(secret_key, plain_text):
        parser = reqparse.RequestParser()
        parser.add_argument('secret_key', type=str, location='args', help='secret_key cannot be converted')
        parser.add_argument('plain_text', type=str, location='args', help='plain_text cannot be converted')
        args = parser.parse_args()
        return AES_encryption(args['secret_key'], args['plain_text'])

    def put(self):
        # input Public key(Secret) then decryption for AES
        # AES_decryption(secret_key, cipher_text):
        json_data = request.get_json(force=True)
        return AES_decryption(json_data['secret_key'], json_data['cipher_text'])
        # parser = reqparse.RequestParser()
        # parser.add_argument('secret_key', type=str, location='form', help='secret_key cannot be converted')
        # parser.add_argument('cipher_text', type=str, location='form', help='cipher_text cannot be converted')
        # args = parser.parse_args()
        # return AES_decryption(args['secret_key'], args['cipher_text'])

api.add_resource(AES, '/aes')

# RSA class
class RSA(Resource):
    """
    for secret exchange: 
    AES: provider client to borker to server
    JWT: secret from transaction
    """

    def get(self):
        # http://127.0.0.1:5000/rsa?public_key_loc=public_key_loc&message=message
        # input secret then return public key encryption value
        # encrypt_RSA(public_key_loc, message):
        parser = reqparse.RequestParser()
        # parser.add_argument('public_key_loc', type=str, location='args', help='public_key_loc cannot be converted')
        parser.add_argument('message', type=str, location='args', help='message cannot be converted')
        parser.add_argument('uuid_ref', type=str, location='args', help='uuid_ref cannot be converted')
        args = parser.parse_args()
        # return filename as secret
        return encrypt_RSA(args['message'], args['uuid_ref'])
        # return encrypt_RSA(args['public_key_loc'], args['message'])

    def post(self):
        # check exist then create RSA key pairs return public key
        # key reference file name      
        # generate_RSA(public_key_loc="public_key")
        import uuid
        uuid_ref = str(uuid.uuid4())[:20]
        return generate_RSA(uuid_ref)
        # parser = reqparse.RequestParser()
        # parser.add_argument('public_key_loc', type=str, location='form', help='public_key_loc cannot be converted')
        # args = parser.parse_args()
        # return generate_RSA(args['public_key_loc'])
    
    def put(self):
        # input Public key(Secret) then decryption for AES
        # check for client(AES) or comsumer(AES, JWT)
        # decrypt_RSA(package, private_key_loc="private_key")
        json_data = request.get_json(force=True)
        file_name = json_data['secret']
        uuid_ref = json_data['uuid_ref']
        return decrypt_RSA(file_name, uuid_ref)

        # parser = reqparse.RequestParser()
        # parser.add_argument('package', type=str, location='form', help='package cannot be converted')
        # args = parser.parse_args()
        # return decrypt_RSA(args['package'])
        # return args['package']

api.add_resource(RSA, '/rsa')

# # MQTT class
# http://stackoverflow.com/questions/3781851/run-a-python-script-from-another-python-script-passing-in-args
# http://xstarcd.github.io/wiki/Python/python_subprocess_study.html
class MQTT(Resource):
    """
    client to broker: provider AES encrypt
    server to broker: provider AES decrypt to mongoDB
    """
    def put(self):
        # publish mqtt 
        # /mqtt/topic/#
        json_data = request.get_json(force=True)
        print "PUBLISH", json_data['topic'], json_data['payload'] , json_data['hostname']
        # AES encrypt or befor by provider
        publish.single(json_data['topic'], json_data['payload'], qos=1, hostname=json_data['hostname'])
        return True, 200

        # parser = reqparse.RequestParser()
        # parser.add_argument('topic', type=str, location='form', help='topic cannot be converted')
        # parser.add_argument('payload', type=str, location='form', help='payload cannot be converted')
        # parser.add_argument('hostname', type=str, location='form', help='hostname cannot be converted')
        # args = parser.parse_args()
        # print "PUBLISH", args['topic'], args['payload'] , args['hostname']
        # # AES encrypt or befor by provider
        # publish.single(args['topic'], args['payload'], qos=1, hostname=args['hostname'])
        # return True, 200

    def post(self):
        # input topic then subscript AES data
        # decryption by secret then use mongoDB store data
        # wildcard: /mqtt/topic/#
        import threading
        t = threading.Thread(target=self.__subscription)
        t.start()
        return True, 200

    def __subscription(self):
        client = mqtt.Client()
        client.on_connect = self.__on_connect
        client.on_message = self.__on_message        
        try:
            client.connect("140.118.109.35", 1883, 60)
        except:
            print "MQTT Broker is not online. Connect later."

        print "Looping..."
        # Blocking call that processes network traffic, dispatches callbacks and
        # handles reconnecting.
        # Other loop*() functions are available that give a threaded interface and a
        # manual interface.
        client.loop_forever()       
    
    def __on_connect(self, client, userdata, flags, rc):
        # The callback for when the client receives a CONNACK response from the server.
        print("Connected with result code "+str(rc))
        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        client.subscribe("#")
    
    def __on_message(self, client, userdata, msg):
        # The callback for when a PUBLISH message is received from the server.
        print(msg.topic+" "+str(msg.payload))
        # AES decrypt or befor by provider
        mongoDB.append(msg.payload)

api.add_resource(MQTT, '/mqtt')

# JWT class
class JWT(Resource):
    """
    after transaction get jwt token
    comsumer use jwt to API get data from mongoDB
    """
    def get(self):
        """
        {
        "exp": 1491360150,
        "transaction": {
            "consumer": "consumer",
            "end": 1491360150000,
            "ip": "ip",
            "provider": "provider",
            "secret": "secret",
            "start": 1490360150000,
            "topic": "topic",
            "transactionKey": "transactionKey",
            "value": "value"
        }
        }
        """
        # validate JWT then use mongoDB return data
        # data encode by AES(secret from jwt)
        # def verify_JWT(jwt_payload):
        
        parser = reqparse.RequestParser()
        parser.add_argument('jwt_payload', type=str, location='args', help='jwt cannot be converted')
        args = parser.parse_args()

        if not verify_JWT(args['jwt_payload']):
            return False, 404
        
        # AES encrypt by comsumer
        return mongoDB

    def post(self):
        """
       {  
            "transactionKey":"transactionKey",
            "secret":"secret",
            "start":1490360150000,
            "end":1491360150000,
            "consumer":"consumer",
            "provider":"provider",
            "value":"value",
            "ip":"ip",
            "topic":"topic"
        }
        """
        # input transaction event create JWT after transaction 
        # def issue_JWT(transaction):
        transaction = request.get_json(force=True)

        return issue_JWT(transaction)


api.add_resource(JWT, '/jwt')

if __name__ == '__main__':
    app.run(debug=True)


