Card.prototype.loadAuthKeysInReader = function(keyNum, key){
    var command = new ByteString('FF 82 20 00', HEX).add(keyNum).concat(new ByteString('06', HEX)).concat(key);
    this.plainApdu(command);
    return {status: this.getStatus()};
}

Card.prototype.loadDefaultAuthKeyInReader = function(keyNum){
    return this.loadAuthKeysInReader(keyNum, new ByteString('FF FF FF FF FF FF', HEX));
}

Card.prototype.readBlock = function(sector, block){
    block = sector*4 + block
    var resp = this.sendApdu(0xFF, 0xB0, 0x00, block, 16);
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

Card.prototype.terminalKey = new ByteString('CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB', HEX);
Card.prototype.masterKey = new ByteString('88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77', HEX);

Card.prototype.calcMAC = function(macChain){
    var iv = new ByteString('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', HEX);
    var mac = Utils.bytes.encryptAES_CBC(macChain, this.terminalKey, iv).right(8).left(4);
    mac = Utils.bytes.encryptAES_CBC(mac, this.masterKey, iv);
    mac = Utils.bytes.encryptAES_CBC(mac, this.terminalKey, iv).right(8).left(4);
    return mac.right(8).left(4);
}

Utils = {
    numbers : {},
    bytes : {},
    time: {},
    tlv: {}
};

Utils.bytes.encryptAES_CBC = function (plain, cypherKey, iv){
    var zeros = (16 - (plain.length % 16)) % 16;

    var plaincpy = plain;
    for( var i=0; i<zeros; i++){
	plaincpy = plaincpy.concat(new ByteString('00', HEX));
    }

    var crypto = new Crypto();
    var key = new Key();
    key.setComponent(Key.AES, cypherKey);

    var cyphered = crypto.encrypt(key, Crypto.AES_CBC, plaincpy, iv);

    return cyphered;
}

Utils.numbers.fixedLengthIntString = function(num, length) {
    return ("00000000000000000" + num).slice(-1 * length);
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

    cloneFormat = cloneFormat.replace("%y", Utils.numbers.fixedLengthIntString(
	    date.getYear() % 100, 2));

    return cloneFormat;
}

Utils.tlv.createNameTLV = function(name){
    var fill = new Array(30 - name.length+1).join('P');
    return new ByteString('C1', HEX).concat(ByteString.valueOf(name.length)).concat(new ByteString(name + fill, ASCII)).left(32);
}

Utils.tlv.createcardNumberTLV = function(number){
    // For number of 16 decimal places, we need 7 bytes
    var numBS = ByteString.valueOf(number);
    var fill = new Array(7-numBS.length+1).join('00');
    
    return new ByteString('C2 07', HEX).concat(new ByteString(fill, HEX)).concat(numBS);
}

Utils.tlv.createExpireTLV = function(date){
    var dStr = Utils.time.formatDate(date, '%m%y');
    return new ByteString('C3 04', HEX).concat(new ByteString(dStr, ASCII));
}

Utils.tlv.createPriceTLV = function(price){
    var priceBS = ByteString.valueOf(price);
    return new ByteString('C6 00', HEX).add(priceBS.length).concat(priceBS);
}

Utils.tlv.createDatetimeTLV = function(date){
    var dateStr = Utils.time.formatDate(date, '%Y%m%d%H%M');
    return new ByteString('E8 00', HEX).add(dateStr.length).concat(new ByteString(dateStr, ASCII));
}

Utils.tlv.createTransactionTLV = function(transType){
    var transCodes = {
	sell: new ByteString('00', HEX),
	take_back: new ByteString('01', HEX),
	reserved: new ByteString('02', HEX),
    };
    
    return new ByteString('EA 01', HEX).concat(transCodes[transType]);
}

Utils.tlv.createStablismentTLV = function(stab){
    return new ByteString('E9 00', HEX).add(stab.length).concat(new ByteString(stab, ASCII));
}

Utils.tlv.createPetitionTypeTLV = function(type){
    var petCodes = {
	authRequest: new ByteString('00', HEX),
	authGaranted: new ByteString('01', HEX),
	authDenied: new ByteString('02', HEX),
	error: new ByteString('03', HEX),
    };
    
    return new ByteString('EA 01', HEX).concat(petCodes[type]);
}

Utils.tlv.createVerificationTypeTLV = function(type){
    var verCodes = {
	pinVerification: new ByteString('00', HEX),
	otherVerification: new ByteString('01', HEX),
	reserved: new ByteString('02', HEX),
    };
    
    return new ByteString('EC 01', HEX).concat(verCodes[type]);
}
