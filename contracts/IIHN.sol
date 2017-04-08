pragma solidity ^0.4.0;

contract IIHN {
    
    // ip as PK
    struct MachineServer { // Struct
        uint activeTime; // required: active timestamp
        string[] topics; // required: MQTT topic secure by username, password
        string publicKey; // Asymmetric key
        string secret; // provider set encrption by MachineServer publicKey
    }
    
    // topic as PK
    struct MachineClient { 
        uint activeTime; // required: active timestamp
        string broker; // required: MQTT broker ip:port
        uint value; // currency per hour 3600sec
        uint score; // default:0 clinet topic score by transactions 
    }
    
    // secret keccak256 hash as PK
    struct Transaction {
        uint start; // start timestamp
        uint end; // end timestamp
        address comsumer;
        address provider;
        uint value; // currency record
        string ip; // for api ip
        string topic; // for data
        string secret; // comsumer set encrption by MachineServer publicKey
    }
    
    // secure by username, password
    struct People {
        string[] serverKeys; // server ip list for API
        mapping(string => MachineServer) machineServers; // ip:MachineServer
        mapping(string => MachineClient) machineClients; // topic:MachineClient key from server
        
        // transaction keys
        bytes32[] consumerKeys; // secret keccak256 hash list
        bytes32[] providerKeys; // secret keccak256 hash list
    }
    
    // transactionKeys ## keccak256(...) returns (bytes32) as secret("string", consumerAddress)
    mapping(bytes32 => Transaction) transactions; // secret:Transaction
    mapping(address => People) peoples;
    
    
    // Events that will be fired on changes.
    event ServerRegister(
        address indexed owner, 
        string ip, 
        uint activeTime,
        string publicKey, 
        string secret
    );
    event ServerDelete(
        address indexed owner, 
        string ip
    );
    event ClientRegister(
        address indexed owner, 
        string ip, 
        string topic,
        uint activeTime,
        string broker, 
        uint value,
        uint score
    );
    event ClientDelete(
        address indexed owner, 
        string ip, 
        string topic
    );
    // transaction event only show secret for development
    event TransactionEvent(
        string secret,
        uint start, 
        uint end, 
        address indexed consumer, 
        address indexed provider, 
        uint value, 
        string ip, 
        string topic
    );
    // event SecretVerify(
    //     address indexed consumer, 
    //     string secret
    // ); 

    // #### Register Contract ####
    // "_ip", "_publicKey", "_secret"
    // Transaction cost: 131896 gas. 
    // Execution cost: 107808 gas.
    function serverRegister(
        string _ip, // PK
        string _publicKey,
        string _secret
    ) 
        returns (bool)
    {
        People people = peoples[msg.sender];
        // if exist
        if (people.machineServers[_ip].activeTime > 0)
            throw;
        
        people.serverKeys.push(_ip);
        
        MachineServer machineServer = people.machineServers[_ip];
        machineServer.activeTime = now;
        machineServer.publicKey = _publicKey;
        machineServer.secret = _secret;
        
        // event 
        ServerRegister(msg.sender, _ip, machineServer.activeTime, _publicKey, _secret);
        
        return true;
    }
    
    // "_ip"
    // Transaction cost: 32061 gas. 
    // Execution cost: 42145 gas.
    function serverDelete(
        string _ip // PK
    )
        returns (bool)
    {
        People people = peoples[msg.sender];
        // if not exist
        if (people.machineServers[_ip].activeTime == 0 || people.machineServers[_ip].topics.length > 0)
            throw;
        // delete array by custom function
        arrayDelete(people.serverKeys, _ip);
        
        delete people.machineServers[_ip];
        
        // event
        ServerDelete(msg.sender, _ip);
        
        return true;
    }
    
    // need server first "_ip", "_publicKey", "_secret"
    // "_ip", "_topic", "_broker", 20
    // Transaction cost: 137758 gas. 
    // Execution cost: 113734 gas.
    function clientRegister(
        string _ip, // server ip
        string _topic, // PK
        string _broker, // required: MQTT broker ip:port
        uint _value
    ) 
        returns (bool)
    {
        People people = peoples[msg.sender];
         // if exist
        if (people.machineServers[_ip].activeTime == 0 || people.machineClients[_topic].activeTime > 0)
            throw;

        MachineServer machineServer = people.machineServers[_ip];
        machineServer.topics.push(_topic);
        
        MachineClient machineClient = people.machineClients[_topic];
        machineClient.activeTime = now;
        machineClient.broker = _broker;
        machineClient.value = _value;
        machineClient.score = 0;
        
        // event
        ClientRegister(msg.sender, _ip, _topic, machineClient.activeTime, _broker, _value, machineClient.score);
        
        return true;
    }
    
    // "_ip", "_topic"
    // Transaction cost: 33281 gas. 
    // Execution cost: 43689 gas.
    function clientDelete(
        string _ip, // server
        string _topic // PK
    )
        returns (bool)
    {
        People people = peoples[msg.sender];
        // if not exist
        if (people.machineClients[_topic].activeTime == 0)
            throw;
            
        // delete server topics by ip
        arrayDelete(people.machineServers[_ip].topics, _topic);
        delete people.machineClients[_topic];
        
        // event
        ClientDelete(msg.sender, _ip, _topic);
        
        return true;
    }
    

    // #### Transaction Contract ####
    // need server first "_ip", "_publicKey", "_secret"
    // need client first "_ip", "_topic", "_broker", 20
    // "_secret", 3600, "0xca35b7d915458ef540ade6068dfe2f44e8fa733c", "_ip", "_topic"
    // Transaction cost: 281170 gas. 
    // Execution cost: 255610 gas.
    function transaction(
        string _secret, // secret string
        uint _duration, // in hour
        address _provider,
        string _ip,
        string _topic
    ) 
        payable 
        returns (bool)
    {
        // ######################### check value and duration???????????????????

        // transactionKeys ## keccak256(...) returns (bytes32) as secret("string", consumerAddress)
        bytes32 transactionKey = keccak256(_secret, msg.sender);
        Transaction transaction = transactions[transactionKey];
        
        // 1. Conditions
        // already have transaction
        if (now <= transaction.end)
            throw;
            
        People provider = peoples[_provider];
        uint value = provider.machineClients[_topic].value;
        
        // if no enough price (value per hour)
        if (msg.value != _duration*value)
            throw;
 
        // 2. Effects
        // need to check server and client owner
        transactions[transactionKey] = Transaction({
            start: now,
            end: now + _duration*3600,
            comsumer: msg.sender,
            provider: _provider,
            value: msg.value,
            ip: _ip,
            topic: _topic,
            secret: _secret
        });
        
        // add transaction key to both people
        People comsumer = peoples[msg.sender];
        
        comsumer.consumerKeys.push(transactionKey);
        provider.providerKeys.push(transactionKey);
        
        // add score
        provider.machineClients[_topic].score++;
        
        // 3. Interaction
        // send money
        if (!_provider.send(msg.value))
            throw;
            
        // evnet
        TransactionEvent(_secret, now, (now + _duration*3600),  msg.sender, _provider, msg.value, _ip, _topic);
        
        return true;
    }
    

    // // secret only consumer know (jwt secret)
    // function secretVerify(
    //     string _secret // secret string
    // )
    //     returns (bool)
    // {
    //     // transactionKeys ## keccak256(...) returns (bytes32) as secret("string", consumerAddress)
    //     bytes32 transactionKey = keccak256(_secret, msg.sender);
    //     Transaction transaction = transactions[transactionKey];
    
    //     // 1. Conditions
    //     // not have transaction or expired
    //     if (now >= transaction.end)
    //         throw;
        
    //     // 2. Effects
    //     SecretVerify(msg.sender, _secret);
        
    //     // 3. Interaction
    //      // add transaction score?
    //     return true;
    // }
    
    
    // #### tool function ####
    function arrayDelete(string[] storage _array, string _text) internal returns (bool) {
        bool index;
        for (uint i = 0; i<_array.length; i++){
            if (index) _array[i-1] = _array[i];
            if (stringsEqual(_text, _array[i])) index = true;
        }
        delete _array[_array.length-1];
        _array.length = _array.length - 1;
        return true;
    }

    function stringsEqual(string _a, string _b) internal returns (bool) {
        bytes memory a = bytes(_a);
        bytes memory b = bytes(_b);
        if (a.length != b.length)
            return false;
        // @todo unroll this loop
        for (uint i = 0; i < a.length; i ++)
            if (a[i] != b[i])
                return false;
        return true;
    }

}