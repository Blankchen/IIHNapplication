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
// testrpc.cmd
// truffle.cmd compile
// truffle.cmd migrate
// npm run build
// truffle.cmd serve
// http://localhost:8080/index.html

//  python api.py

myApp.controller('myController', function ($scope, $http) {
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
    window.web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:8545"));
  }
  // ng model for account filter
  $scope.selectAccount = '';
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
  // form model
  $scope.form = {
    client: {
      broker: "140.118.109.35:1883"
    },
    clientDelete: {},
    server: {},
    serverDelete: {},
    transaction: {} 
  }
  // function
  $scope.serverRegister = serverRegister;
  $scope.serverDelete = serverDelete;
  $scope.clientRegister = clientRegister;
  $scope.clientDelete = clientDelete;
  $scope.transaction = transaction;
  $scope.api = api;  
  //  MQTTpublish & jwt
  $scope.mqtt = {};
  $scope.jwt = {};

  activate();

  function activate() {
    start();

    setEventInfo();
    eventFilter();
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
      // accounts = accs;
      // account = accounts[0];    
      // console.log(accs);
      $scope.account.list = accs;
      $scope.account.my = accs[0];
      
      let balance = web3.eth.getBalance(accs[0]);
      $scope.account.myBalance = balance.plus(21).toString(10);
      // console.log( $scope.account);
      $scope.$apply();
    });
    
  }

  function api() {
    let url = "http://127.0.0.1:5000";
    return {
      // [get] /aes: for MQTT publish 
      AESencryption: function (secret_key, plain_text) {
        return $http.get(url+"/aes", {params: { secret_key:secret_key, plain_text:plain_text }});
      },
      // [put] /aes: for JWT get API
      AESdecryption: function (secret_key, cipher_text) {
        return $http.put(url+"/aes", {secret_key:secret_key, cipher_text:cipher_text });
      },
      // [get] /rsa: for serverRegister and transaction RSA(secret)
      RSAencryption: function (arg1, ar2) {
        let message = $scope.form[arg1][ar2];
        $http.get(url+"/rsa", {params: { message:message }}).then(function(response) {
          console.log("RSAencryption", message, response.data);
          $scope.form[arg1][ar2] = response.data;
        });
      },
      // [post] /rsa: generate rsa before serverRegister
      RSAgenerate: function (arg1, ar2) {
        $http.post(url+"/rsa").then(function(response) {
          console.log("RSAgenerate", response.data);
          $scope.form[arg1][ar2] = response.data;
        });
      },
      // [put] /rsa: after event decrypt RSA(secret)
      RSAdecryption: function (encryPackage) {
        return $http.put(url+"/rsa", {package:encryPackage });
      },
      // [put] /mqtt: publish data
      MQTTpublish: function (topic, payload, hostname) {
        return $http.put(url+"/mqtt", {topic:topic, payload:payload, hostname:hostname });
      },
      // [post] /mqtt: subscript data after serverRegister event
      MQTTsubscription: function () {
        return $http.post(url+"/mqtt");
      },
      // [get] /jwt: jwt API get mqtt data
      JWTverifyAPI: function (jwt_payload) {
        return $http.get(url+"/jwt", {params: {jwt_payload:jwt_payload }});
      },
      // [post] /jwt: issue jwt after transaction event
      JWTissue: function (transaction) {
        return $http.post(url+"/jwt", {transaction:transaction });
      },
    }           
  }

  api().AESencryption('secret', 'test')
    .then(function(response) {
       let cipher_text = response.data;
       console.log('===', cipher_text);

       api().AESdecryption('secret', cipher_text)
        .then(function(response) {
          let plain_text = response.data;
          console.log('===', plain_text);
        });;
    });


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
        transactionDict[data.transactionKey] = data;
        localStorage.setItem(transactionKey, JSON.stringify(transactionDict));
      }
    }
  }

  function setEventInfo() {
    $scope.events.clientList = db().clientRead();
    $scope.events.serverList = db().serverRead();
    $scope.events.transactionList = db().transactionRead();
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

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.serverRegister(ip, publicKey, secret, { from: account, gas: 241896 });
    }).then(function () {
      console.log("Transaction complete!");
      setTimeout(function() {
        setEventInfo();
      }, 1000);      
    }).catch(function (e) {
      console.log(e);
      console.log("Error serverRegister; see log.");
    });
  }

  function serverDelete(model) {
    var ip = model.ip;

    console.log("Initiating transaction... (please wait)", model);

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.serverDelete(ip, { from: account, gas: 185145 });
    }).then(function () {
      console.log("Transaction complete!");
      setTimeout(function() {
        setEventInfo();
      }, 1000); 
    }).catch(function (e) {
      console.log(e);
      console.log("Error serverDelete; see log.");
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

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.clientRegister(ip, topic, broker, value, { from: account, gas: 247758 });
    }).then(function () {
      console.log("Transaction complete!");
      setTimeout(function() {
        setEventInfo();
      }, 1000); 
    }).catch(function (e) {
      console.log(e);
      console.log("Error clientRegister; see log.");
    });
  }

  function clientDelete(model) {
    // var amount = parseInt(document.getElementById("amount").value);
    // var receiver = document.getElementById("receiver").value;
    var ip = model.ip;
    var topic = model.topic;

    console.log("Initiating transaction... (please wait)", model);

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.clientDelete(ip, topic, { from: account, gas: 95145 });
    }).then(function () {
      console.log("Transaction complete!");
      setTimeout(function() {
        setEventInfo();
      }, 1000); 
    }).catch(function (e) {
      console.log(e);
      console.log("Error clientDelete; see log.");
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

    var meta;
    var account = $scope.account.my;
    IIHN.deployed().then(function (instance) {
      meta = instance;
      return meta.transaction(secret, duration, provider, ip, topic, { from: account, gas: 535610, value: value });
    }).then(function () {
      console.log("Transaction complete!");
      setTimeout(function() {
        setEventInfo();
      }, 1000); 
    }).catch(function (e) {
      console.log(e);
      console.log("Error transaction; see log.");
    });
  }


});


