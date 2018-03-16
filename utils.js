Card.prototype.loadAuthKeysInReader = function(keyNum, key){
    var command = new ByteString('FF 82 20 00', HEX).add(keyNum).concat(new ByteString('06', HEX)).concat(key);
    this.plainApdu(command);
    return {status: this.getStatus()};
}

Card.prototype.loadDefaultAuthKeyInReader = function(keyNum){
    return this.loadAuthKeysInReader(keyNum, new ByteString('FF FF FF FF FF FF', HEX));
}

Card.prototype.readBlock = function(sector, block, length){
    block = sector*4 + block
    var resp = this.sendApdu(0xFF, 0xB0, 0x00, block, length);
    return {
	data: resp,
	status: this.getStatus()
    };
}

Card.prototype.writeBlock = function(sector, block, data){
    block = 4*sector + block;

    var command = new ByteString('FF D6 00 00',HEX).add(block).concat(new ByteString('00', HEX).add(data.length)).concat(data);
    this.plainApdu(command);
    return {status: this.getStatus()};
}

Card.prototype.authenticateBlock = function(sector, block, keyNumber, keyType){
    var kTypes = {A: 0x60, B: 0x61};    
    keyNumber = 'undefined' == typeof keyNumber? 0: keyNumber;
    keyType = 'undefined' == typeof keyType? 'A': keyType;
    block = sector*4 + block;
    var command = new ByteString('FF 86 00 00 05', HEX);
    var authData = new ByteString('01 00 00 00 00', HEX).add(block*256*256+kTypes[keyType]*256+keyNumber);
    this.plainApdu(command.concat(authData));
    return {status: this.getStatus()};
    
}

Card.prototype.authenticateSector = function(sector, keyNumber, keyType){
    return this.authenticateBlock(sector, 0, keyNumber, keyType);
}

Card.prototype.valueOperation =  function(sector, block, oper, value){
    block = sector*4 + block;
    var command = new ByteString('FF D7 00 00 05', HEX).add(block*256);
    var data = new ByteString('00', HEX).add(oper).concat(new ByteString('00 00 00 00', HEX).add(value));
    this.plainApdu(command.concat(data));
    return {status: this.getStatus()};
}

Card.prototype.setAsValueBlock = function(sector, block, value){
    return this.valueOperation(sector, block, 0, value)
}

Card.prototype.increment = function(sector, block, value){
    return this.valueOperation(sector, block, 1, value)
}

Card.prototype.decrement = function(sector, block, value){
    return this.valueOperation(sector, block, 2, value)
}

Card.prototype.readValueBlock = function(sector, block){
    block = sector*4 + block;
    var resp = this.sendApdu(0xFF, 0xB1, 0, block, 0);
    return {data: resp, status: this.getStatus()};
}

Card.prototype.getSerialNumber = function(){
    var resp = this.sendApdu(0xFF, 0xCA, 0, 0, 4);
    return {
	data: resp,
	status: this.getStatus()
    };
}

Card.prototype.getStatus = function() {
    return this.SW.toString(16);
}

Card.prototype.calcMAC = function(macChain, serialNum){
    
    var masterKey = new ByteString('D1 1C 3E 03 9E 62 39 A8', HEX)
    var key = masterKey.xor(new ByteString('00 00 00 00', HEX).concat(serialNum));
    
    var iv = new ByteString('73 2B BD 76', HEX).concat(serialNum.add(1));
    var mac = Utils.bytes.encryptDES_CBC(macChain, key, iv);
    return mac.right(8).left(4);
}

Card.prototype.fillMAC = function(mac){
    return new ByteString('68 C3 DB 5B 01 29', HEX).concat(mac).concat(new ByteString('63 65 5F E6 FC ED', HEX));
}

Card.prototype.composeCalcAndFillMAC = function(credit, emissionDate, transport, payMethod, emitter, serial){
    // for a max value of 15000, we need 2 bytes
    var creditSTR = new ByteString('00 00', HEX).add(credit).toString(HEX);
    var macChain = creditSTR+emissionDate+transport+payMethod+emitter;
    var mac = this.calcMAC(new ByteString(macChain, ASCII), serial);
    return this.fillMAC(mac);
}

Utils = {
    numbers : {},
    bytes : {},
    time: {}
};

Utils.numbers.fixedLengthIntString = function(num, length) {
    return ("00000000000000000" + num).slice(-1 * length);
}

Utils.bytes.encryptDES_CBC = function (plain, cypherKey, iv) {
    var crypto = new Crypto();
    var key = new Key();
    key.setComponent(Key.DES, cypherKey);
    
    var plaincpy = plain.pad(Crypto.ISO9797_METHOD_2, true);

    var cyphered = crypto.encrypt(key, Crypto.DES_CBC, plaincpy, iv);

    return cyphered;
}

Utils.bytes.decryptDES_CBC = function (crypted, cypherKey, iv) {

    var crypto = new Crypto();
    var key = new Key();
    key.setComponent(Key.DES, cypherKey);

    var decrypted = crypto.decrypt(key, Crypto.DES_CBC, crypted, iv);
    return decrypted;
}

Utils.bytes.circularShift = function(val, direction, places){
    places = 'undefined' == typeof places? 1: places;
    if(direction == 'l')
	return val.right(val.length - places).concat(val.left(places));
    if(direction == 'r')
	return val.right(places).concat(val.left( val.length - places));
    throw "[ERROR] '" + direction + "' is not a valid direction value"
}

Utils.time.getToday = function() {
    var today = new Date()
    today.setHours(0);
    today.setMinutes(0);
    today.setSeconds(0);
    today.setMilliseconds(0);
    return today;
}

Utils.time.formatRegex = function(format) {
    var dictionary = {
	'%Y' : '\\d{4}',
	'%m' : '\\d{2}',
	'%d' : '\\d{2}'
    }

    var regex = '^' + format + '$';

    for ( var key in dictionary) {
	regex = regex.replace(key, '(' + dictionary[key] + ')');
    }
    return RegExp(regex);
}

Utils.time.str2date = function(dateString, format) {
    var options = [ '%Y', '%m', '%d' ];

    var equivalences = {
	'%Y' : 'year',
	'%m' : 'month',
	'%d' : 'date'
    };

    var regex = Utils.time.formatRegex(format);
    var groups = [];
    for (var i = 0; i < format.length; i++) {
	var index = format.search(options[i]);
	if (index >= 0)
	    groups[index] = equivalences[options[i]];
    }
    groups = groups.filter(function(elem) {
	return elem !== undefined;
    });

    var matches = dateString.match(regex);
    if (matches == null) {
	print('date invalid');
	exit;
    }
    var data = [];
    for (var i = 0; i < groups.length; i++) {
	data[groups[i]] = parseInt(matches[i + 1]);
    }
    var date = new Date(data['year'], data['month'] - 1, data['date'], 0, 0, 0,
	    0);
    return date;
}

Utils.time.formatDate = function(date, format) {

    // Replacing Full year
    var cloneFormat = format.replace("%Y", date.getFullYear());

    // Replacing months
    cloneFormat = cloneFormat.replace("%m", Utils.numbers.fixedLengthIntString(date
	    .getMonth() + 1, 2));

    // Replacing date
    cloneFormat = cloneFormat.replace("%d", Utils.numbers.fixedLengthIntString(
	    date.getDate(), 2));
    
    cloneFormat = cloneFormat.replace("%H", Utils.numbers.fixedLengthIntString(
	    date.getHours(), 2));
    
    cloneFormat = cloneFormat.replace("%M", Utils.numbers.fixedLengthIntString(
	    date.getMinutes(), 2));

    return cloneFormat;
}
