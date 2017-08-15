# required 
- Truffle: https://github.com/trufflesuite/truffle
- (Blockchain Client) testrpc: https://github.com/ethereumjs/testrpc
- (Backend Services) Flask-RESTful: https://github.com/flask-restful/flask-restful
- (Backend Services) PyJW: https://pyjwt.readthedocs.io/en/latest/installation.html
- (Backend Services) pycrypto: https://github.com/dlitz/pycrypto
- (MQTT) paho.mqtt.python: https://github.com/eclipse/paho.mqtt.python#installation
- (MQTT) Mosquitto: https://mosquitto.org/

# truffle documentation
- http://truffleframework.com/tutorials/building-testing-frontend-app-truffle-3
- http://truffleframework.com/docs/

# How to start


```bash
$ cd this-project

# install the project's dependencies
$ npm install
# fast install (via Yarn, https://yarnpkg.com)
$ yarn install  # or yarn

# start blokcchain test client
$ testrpc.cmd 
# start python backend
$ python api.py

# compile smart contract
$ truffle.cmd compile
# migrate contract to testrpc
$ truffle.cmd migrate --reset

# build website
$ npm run build
# start web service
$ truffle.cmd serve
# browser to http://localhost:8080/index.html


```

# truffle-init-webpack
Example webpack project with Truffle. Includes contracts, migrations, tests, user interface and webpack build pipeline.

## Usage

To initialize a project with this exapmple, run `truffle init webpack` inside an empty directory.

## Building and the frontend

1. First run `truffle compile`, then run `truffle migrate` to deploy the contracts onto your network of choice (default "development").
1. Then run `npm run dev` to build the app and serve it on http://localhost:8080

## Possible upgrades

* Use the webpack hotloader to sense when contracts or javascript have been recompiled and rebuild the application. Contributions welcome!

## Common Errors

* **Error: Can't resolve '../build/contracts/MetaCoin.json'**

This means you haven't compiled or migrated your contracts yet. Run `truffle compile` and `truffle migrate` first.

Full error:

```
ERROR in ./app/main.js
Module not found: Error: Can't resolve '../build/contracts/MetaCoin.json' in '/Users/tim/Documents/workspace/Consensys/test3/app'
 @ ./app/main.js 11:16-59
```


## Directory Structure


```
.
├── app  <- User Interface (AngularJS, Bootstrap and web3.js)
│   ├── javascripts
│   │   └── app.js
│   ├── stylesheets
│   │   └── app.css
│   └── index.html
├── build  <- build smart contracts
├── contracts <- smart contract solidity source
├── keys <- RSA and AES keys
├── migrations
├── node_modules
├── test
├── api.py <- Backend Services (flask-restful, PyJWT and pycrypto)
├── package.json <- Truffle 3 webpack npm setting
└── README.md

```