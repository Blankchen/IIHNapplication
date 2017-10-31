// Import libraries we need.
import { default as Web3 } from 'web3';
import { default as contract } from 'truffle-contract'

// Import our contract artifacts and turn them into usable abstractions.
// import metacoin_artifacts from '../../build/contracts/MetaCoin.json'
import IIHN_artifacts from '../../build/contracts/IIHN.json'

var myApp = angular.module('myApp', ['ngAnimate', 'ngSanitize', 'ui.bootstrap']);

// myApp.config(function ($httpProvider) {
//     $httpProvider.defaults.withCredentials = true;
//     // http://stackoverflow.com/questions/17064791/http-doesnt-send-cookie-in-requests
// })


// C:\Users\Blank\Blockchain  (truffle-init-webpack@0.0.1)
// testrpc.cmd --db="C:\Users\Blank\Blockchain\db"
// truffle.cmd compile
// truffle.cmd migrate --reset
// npm run build
// truffle.cmd serve
// http://localhost:8080/index.html

//  python api.py

// restart clean browser localstorage, keys folder

myApp.controller('myController', function ($scope, $http, $timeout) {
  // smart contract
  var IIHN = contract(IIHN_artifacts);
  // var accounts;
  // var account;

  // Checking if Web3 has been injected by the browser (Mist/MetaMask)
  if (typeof web3 !== 'undefined') {
    console.warn("Using web3 detected from external source. If you find that your accounts don't appear or you have 0 MetaCoin, ensure you've configured that source properly. If using MetaMask, see the following link. Feel free to delete this warning. :) http://truffleframework.com/tutorials/truffle-and-metamask")
    // Use Mist/MetaMask's provider
    window.web3 = new Web3(web3.currentProvider);
  } else {
    console.warn("No web3 detected. Falling back to http://localhost:8545. You should remove this fallback when you deploy live, as it's inherently insecure. Consider switching to Metamask for development. More info here: http://truffleframework.com/tutorials/truffle-and-metamask");
    // fallback - use your fallback strategy (local node / hosted node + in-dapp id mgmt / fail)
    // window.web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
    window.web3 = new Web3(new Web3.providers.HttpProvider("http://140.118.109.35:8545"));
  }
  // ng model for account filter
  $scope.selectAccount = '';
  // ng model for transaction
  $scope.selectTxClient = undefined;
  // ng model for mqtt client
  $scope.selectMQTTClient = undefined;
  // ng model for transaction
  $scope.selectTransaction = undefined;
  // variable
  $scope.account = {
    my: '',
    myBalance: '',
    list: []
  };
  // blockchain event
  $scope.events = {
    clientList: [],
    serverList: [],
    transactionList: [] 
  };
  // (ui.bootstrap.collapse)
  $scope.collapse = {
    isClient: true,
    isServer: true,
    isTransaction: true,
    isOthers: true
  }
  // form model
  $scope.form = {
    client: {
      ip: "140.118.109.35",
      broker: "140.118.109.35:1883"
    },
    clientDelete: {},
    server: {
      ip: "140.118.109.35"
    },
    serverDelete: {},
    transaction: {} 
  }
  //  MQTTpublish & jwt
  $scope.mqtt = {};
  $scope.jwt = {};
  // function
  $scope.serverRegister = serverRegister;
  $scope.serverDelete = serverDelete;
  $scope.clientRegister = clientRegister;
  $scope.clientDelete = clientDelete;
  $scope.transaction = transaction;
  $scope.getBalance = getBalance;
  $scope.api = api;  
  $scope.setTransaction = setTransaction;
  $scope.setMQTTClient = setMQTTClient;
  $scope.jsonParser = jsonParser;
  // ajax alert message
  $scope.alerts = [];
  $scope.closeAlert = function(index) {
    $scope.alerts.splice(index, 1);
  };
  
  activate();

  function activate() {
    localStorage.clear();
    start();

    eventFilter();
    setTimeout(function() {
      setEventInfo();
    }, 1000); 
  }

  function start() {
    // Bootstrap the MetaCoin abstraction for Use.
    IIHN.setProvider(web3.currentProvider);

    // Get the initial account balance so it can be displayed.
    web3.eth.getAccounts(function (err, accs) {
      if (err != null) {
        alert("There was an error fetching your accounts.");
        return;
      }

      if (accs.length == 0) {
        alert("Couldn't get any accounts! Make sure your Ethereum client is configured correctly.");
        return;
      }
      // get account list 10
      $scope.account.list = accs;
      // set default account
      $scope.account.my = accs[0];
      // set filter account
      $scope.selectAccount = accs[0];
      
       getBalance();
      // let balance = web3.eth.getBalance(accs[0]);
      // $scope.account.myBalance = balance.plus(21).toString(10);
      // console.log( $scope.account);
      $scope.$apply();
    });
  }

  function getBalance() {
    let account = $scope.account.my;
    let balance = web3.eth.getBalance(account);
    $scope.account.myBalance = balance.plus(21).toString(10);
  }

  function api() {
    let url = "http://140.118.109.35:5000";
    return {
      // [get] /aes: for MQTT publish 
      AESencryption: function (arg1, arg2) {
        let secret_key = $scope[arg1].secret;
        let uuid_ref = $scope[arg1].uuid_ref;
        let plain_text = $scope[arg1][arg2];
        if(!secret_key || !uuid_ref || !plain_text) return;
        $http.get(url+"/aes", {params: { secret_key:secret_key, plain_text:plain_text, uuid_ref:uuid_ref }}).then(function(response) {
          console.log("AESencryption", response.data);
          $scope[arg1][arg2] = response.data;
        });
      },
      // [put] /aes: for JWT get API
      AESdecryption: function (arg1, arg2) {
        let secret_key = $scope[arg1].secret;
        let uuid_ref = $scope[arg1].uuid_ref;
        let cipher_text = $scope[arg1][arg2];
        if(!secret_key || !uuid_ref || !cipher_text) return;
        $http.put(url+"/aes", {secret_key:secret_key, cipher_text:cipher_text, uuid_ref:uuid_ref }).then(function(response) {
          console.log("AESencryption", response.data);
          $scope[arg1][arg2] = response.data;
        });
      },
      // [get] /rsa: for serverRegister and transaction RSA(secret)
      RSAencryption: function (arg1, arg2, arg3) {
        let message = $scope.form[arg1][arg2];
        let uuid_ref = $scope.form[arg1][arg3];
        if (!message || !uuid_ref) return;
        $http.get(url+"/rsa", {params: { message:message, uuid_ref:uuid_ref }}).then(function(response) {
          console.log("RSAencryption", message, response.data);
          $scope.form[arg1][arg2] = response.data;
        });
      },
      // [post] /rsa: generate rsa before serverRegister
      RSAgenerate: function (arg1, arg2) {
        $http.post(url+"/rsa").then(function(response) {
          console.log("RSAgenerate", response.data);
          $scope.form[arg1][arg2] = response.data;
        });
      },
      // [put] /rsa: after event decrypt RSA(secret)
      RSAdecryption: function (arg1, arg2, arg3) {
        let secret = $scope.form[arg1][arg2];
        let uuid_ref = $scope.form[arg1][arg3];
        if (!secret || !uuid_ref) return;
        $http.put(url+"/rsa", { secret:secret, uuid_ref:uuid_ref }).then(function(response) {
          console.log("RSAdecryption", response.data);
          $scope.form[arg1][arg2] = response.data;
        });
      },
      // [put] /mqtt: publish data
      MQTTpublish: function (topic, payload, hostname) {
        $http.put(url+"/mqtt", {topic:topic, payload:payload, hostname:hostname }).then(function(response) {
          console.log("MQTTpublish", response.data);
          addAlert({ type: 'success', msg: "MQTT start publish data." })
        });
      },
      // [post] /mqtt: subscript data after serverRegister event
      MQTTsubscription: function (secret, uuid_ref) {
        if (!secret || !uuid_ref) return;
        $http.post(url+"/mqtt", { secret:secret, uuid_ref:uuid_ref }).then(function(response) {
          console.log("MQTTsubscription", response.data);
          addAlert({ type: 'success', msg: "MQTT start subscript data." })
        });
      },
      // [get] /jwt: jwt API get mqtt data
      JWTverifyAPI: function (jwt_payload, uuid_ref) {
        if (!jwt_payload || !uuid_ref) return;
        $http.get(url+"/jwt", {params: {jwt_payload:jwt_payload, uuid_ref:uuid_ref }}).then(function(response) {
          console.log("JWTverifyAPI", response.data);
          $scope.jwt["json_data"] = response.data;
        }, function(response) {
          //Second function handles error
          addAlert({ type: 'danger', msg: "JWT veryfy error; see log." })
        });
      },
      // [post] /jwt: issue jwt after transaction event
      JWTissue: function (transaction) {
        // set secret when select chenage
        $scope.jwt["uuid_ref"] = $scope.events.serverList[transaction.ip].publicKey; 
        $scope.jwt["secret"] = transaction.secret;
        console.log("JWTissue uuid_ref", $scope.jwt);
        $http.post(url+"/jwt", {transaction:transaction }).then(function(response) {
          console.log("JWTissue", response.data);
          $scope.jwt["jwt_payload"] = response.data;
        });
      },
    }           
  }

  function setTransaction(client) {
    if (!client) return;
    // set transaction from client
    let secret = $scope.form.transaction.secret;
    let duration = $scope.form.transaction.duration;
    let value = duration? +client.value*duration:+client.value;
    // hide form value
    let publicKey = $scope.events.serverList[client.ip].publicKey;
    $scope.form.transaction = {
      secret: secret,
      duration: duration,
      provider: client.owner,
      ip: client.ip,
      topic: client.topic,
      value: value,
      publicKey: publicKey
    };
    console.log("setTransaction", $scope.form.transaction);
  }

  function setMQTTClient(client) {
    if (!client) return;
    let payload = $scope.mqtt.payload;
    // hide form value
    let secret = $scope.events.serverList[client.ip].secret;    
    let uuid_ref = $scope.events.serverList[client.ip].publicKey; 
    $scope.mqtt = {
      topic: client.topic,
      broker: client.broker,
      payload: payload,
      secret: secret,
      uuid_ref: uuid_ref
    }
    console.log("setMQTTClient", $scope.mqtt);
  }

  function jsonParser() {
    $scope.jwt.json_data = angular.fromJson($scope.jwt.json_data);
  }

  function db() {
    const serverKey = 'serverKey';
    const clientKey = 'clientKey';
    const transactionKey = 'transactionKey';
    var serverDict = JSON.parse(localStorage.getItem(serverKey) || '{}');
    var clientDict = JSON.parse(localStorage.getItem(clientKey) || '{}');
    var transactionDict = JSON.parse(localStorage.getItem(transactionKey) || '{}');

    return {
      serverRead: function () {
        return serverDict;
      },
      serverInsert: function (data) {
        serverDict[data.ip] = data;
        localStorage.setItem(serverKey, JSON.stringify(serverDict));
      },
      serverDelete: function (data) {
        delete serverDict[data.ip];
        localStorage.setItem(serverKey, JSON.stringify(serverDict));
      },
      clientRead: function () {
        return clientDict;
      },
      clientInsert: function (data) {
        clientDict[data.topic] = data;        
        localStorage.setItem(clientKey, JSON.stringify(clientDict));
      },
      clientDelete: function (data) {
        delete clientDict[data.topic];
        localStorage.setItem(clientKey, JSON.stringify(clientDict));
      },
      transactionRead: function () {
        return transactionDict;
      },
      transactionInsert: function (data) {
        transactionDict[data.secret] = data;
        localStorage.setItem(transactionKey, JSON.stringify(transactionDict));
        // add client score
        clientDict[data.topic].score = parseInt(clientDict[data.topic].score) + 1;
        localStorage.setItem(clientKey, JSON.stringify(clientDict));
      }
    }
  }

  function setEventInfo() {
    $scope.events.clientList = db().clientRead();
    $scope.events.serverList = db().serverRead();
    $scope.events.transactionList = db().transactionRead();
    // get balance again
    getBalance()
    $scope.$applyAsync();
  }

  function eventFilter() {
    var meta;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      // watch for an event with {some: 'args'}
      var myEvent = meta.allEvents({ fromBlock: 0, toBlock: 'latest' });
      myEvent.watch(function (error, result) {
        if (!error) {
          console.log(result);
          switch (result.event) {
            case 'ServerRegister':
              db().serverInsert(result.args);
              break;
            case 'ServerDelete':
              db().serverDelete(result.args);
              break;
            case 'ClientRegister':
              db().clientInsert(result.args);
              break;
            case 'ClientDelete':
              db().clientDelete(result.args);
              break;
            case 'TransactionEvent':
              db().transactionInsert(result.args);
              break;
            default:
              console.error('No event', result.event);
          }
        }


      });

    }).catch(function (e) {
      console.log(e);
      console.log("Error eventFilter.");
    });
  }

  function serverRegister(model) {
    var ip = model.ip;
    // var topic = model.topic;
    var publicKey = model.publicKey;
    // RSA(secret) provider
    var secret = model.secret;

    console.log("Initiating transaction... (please wait)", model);
    addAlert({ type: 'info', msg: "Initiating transaction... (please wait)" })

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.serverRegister(ip, publicKey, secret, { from: account, gas: 257715  });
    }).then(function () {
      console.log("Transaction complete!");
      addAlert({ type: 'success', msg: "Transaction complete!" })
      // creat MQTT if transaction ok
      api().MQTTsubscription(secret, publicKey);
      // need response

      setTimeout(function() {
        setEventInfo();
      }, 1000);      
    }).catch(function (e) {
      console.log(e);
      console.log("Error serverRegister; see log.");
      addAlert({ type: 'danger', msg: "Error serverRegister; see log." })
    });
  }

  function serverDelete(model) {
    var ip = model.ip;

    console.log("Initiating transaction... (please wait)", model);
    addAlert({ type: 'info', msg: "Initiating transaction... (please wait)" })

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.serverDelete(ip, { from: account, gas: 185145 });
    }).then(function () {
      console.log("Transaction complete!");
      addAlert({ type: 'success', msg: "Transaction complete!" })
      setTimeout(function() {
        setEventInfo();
      }, 1000); 
    }).catch(function (e) {
      console.log(e);
      console.log("Error serverDelete; see log.");
      addAlert({ type: 'danger', msg: "Error serverDelete; see log." })
    });
  }

  function clientRegister(model) {
    // var amount = parseInt(document.getElementById("amount").value);
    // var receiver = document.getElementById("receiver").value;
    var ip = model.ip;
    var topic = model.topic;
    var broker = model.broker;
    var value = model.value;

    console.log("Initiating transaction... (please wait)", model);
    addAlert({ type: 'info', msg: "Initiating transaction... (please wait)" })

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.clientRegister(ip, topic, broker, value, { from: account, gas: 247758 });
    }).then(function () {
      console.log("Transaction complete!");
      addAlert({ type: 'success', msg: "Transaction complete!" })
      setTimeout(function() {
        setEventInfo();
      }, 1000); 
    }).catch(function (e) {
      console.log(e);
      console.log("Error clientRegister; see log.");
      addAlert({ type: 'danger', msg: "Error clientRegister; see log." })
    });
  }

  function clientDelete(model) {
    // var amount = parseInt(document.getElementById("amount").value);
    // var receiver = document.getElementById("receiver").value;
    var ip = model.ip;
    var topic = model.topic;

    console.log("Initiating transaction... (please wait)", model);
    addAlert({ type: 'info', msg: "Initiating transaction... (please wait)" })

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.clientDelete(ip, topic, { from: account, gas: 95145 });
    }).then(function () {
      console.log("Transaction complete!");
      addAlert({ type: 'success', msg: "Transaction complete!" })
      setTimeout(function() {
        setEventInfo();
      }, 1000); 
    }).catch(function (e) {
      console.log(e);
      console.log("Error clientDelete; see log.");
      addAlert({ type: 'danger', msg: "Error clientDelete; see log." })
    });
  }

  function transaction(model) {
    // RSA(secret) consumer
    var secret = model.secret;
    var duration = model.duration;
    var provider = model.provider;
    var ip = model.ip;
    var topic = model.topic;
    // virtual currency
    var value = model.value;

    console.log("Initiating transaction... (please wait)", model);
    addAlert({ type: 'info', msg: "Initiating transaction... (please wait)" })

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.transaction(secret, duration, provider, ip, topic, { from: account, gas: 535610, value: value });
    }).then(function () {
      console.log("Transaction complete!");
      addAlert({ type: 'success', msg: "Transaction complete!" })
      setTimeout(function() {
        setEventInfo();
      }, 1000); 
    }).catch(function (e) {
      console.log(e);
      console.log("Error transaction; see log.");
      addAlert({ type: 'danger', msg: "Error transaction; see log." })
    });
  }

  function addAlert(alert) {
    // { type: 'danger', msg: 'Oh snap! Change a few things up and try submitting again.' },
    // { type: 'success', msg: 'Well done! You successfully read this important alert message.' }
    $scope.alerts.push(alert);
    $timeout(function() {
      $scope.alerts.shift();
    }, 3000);
  };

});


