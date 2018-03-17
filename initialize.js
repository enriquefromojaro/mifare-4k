load('utils.js')

function createNameTLV(name){
    var fill = new Array(30 - name.length+1).join('P');
    return new ByteString('C1', HEX).concat(ByteString.valueOf(name.length)).concat(new ByteString(name + fill, ASCII)).left(32);
}

function createcardNumberTLV(number){
    // For number of 16 decimal places, we need 7 bytes
    var numBS = ByteString.valueOf(number);
    var fill = new Array(7-numBS.length+1).join('00');
    
    return new ByteString('C2 07', HEX).concat(new ByteString(fill, HEX)).concat(numBS);
}

function createExpireTLV(date){
    var dStr = Utils.time.formatDate(date, '%m%y');
    return new ByteString('C3 04', HEX).concat(new ByteString(dStr, ASCII));
}

function initializeCard(name, number, expirationDate){
    var nameTLV = createNameTLV(name);
    var numberTLV = createcardNumberTLV(number);
    var expDateTLV = createExpireTLV(expirationDate);
    var card  = new Card();
    var atr = card.reset(Card.RESET_COLD);
    try{
	var card  = new Card();
	var atr = card.reset(Card.RESET_COLD);
	var resp = card.loadDefaultAuthKeyInReader(0);
	if(resp.status !== '9000')
	    throw '[ERROR] Error loading default key in reader (position' + i + ') : ' + resp.status;
	
	var serial = card.getSerialNumber();
	if(serial.status === '9000')
	    serial = serial.data;
	else
	    throw '[ERROR] Error retrieving serial number: ' + serial.status;
	
	// Authenticating against sector 1
	var resp = card.authenticateSector(1);
	if(resp.status !== '9000')
	    throw '[ERROR] Error authenticating against sector 1: ' + resp.status;
	
	// Writing name TLV in sector 1 blocks 0 and 1
	resp = card.writeBlock(1, 0, nameTLV.left(16));
	if (resp.status !== '9000')
	    throw '[ERROR] Card error writing the left part of the name TLV in sector 1 block 0: ' + resp.status;
	resp = card.writeBlock(1, 1, nameTLV.right(16));
	if (resp.status !== '9000')
	    throw '[ERROR] Card error writing the right part of the name TLV in sector 1 block 0: ' + resp.status;
	
	// Writing the card number TLV and the expiration date TLV in sector 1 block 2
	// The number TLV is exactly 9 bytes long and the expiration date one 6, so they can go in the same block
	
	var numExp = numberTLV.concat(expDateTLV).concat(new ByteString('P', ASCII));
	resp = card.writeBlock(1, 2, numExp);
	if (resp.status !== '9000')
	    throw '[ERROR] Card error writing the TLVs of card number and expiration date in in sector 1 block 2: ' + resp.status;
	
	print('CARD INITIALIZED');
    }catch(err){
	print(err);
    }finally{
	card.close();
    }
};

initializeCard('Enrique Fernandez Romojaro', 0123456789012345, new Date(2022, 05)); // June of 2022
