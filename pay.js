load('utils.js')

function pay(price){
    var stabCode = 'EST000001';

    var priceTLV = Utils.tlv.createPriceTLV(Math.floor(price*100));

    var datetimeTLV = Utils.tlv.createDatetimeTLV(new Date());

    var transactionTLV = Utils.tlv.createTransactionTLV('sell');

    var stabTLV = Utils.tlv.createStablismentTLV(stabCode);

    var petTypeTLV = Utils.tlv.createPetitionTypeTLV('authRequest');

    var verifTLV = Utils.tlv.createVerificationTypeTLV('pinVerification');

    var card  = new Card();
    var atr = card.reset(Card.RESET_COLD);
    try{
	var card  = new Card();
	var atr = card.reset(Card.RESET_COLD);
	var resp = card.loadDefaultAuthKeyInReader(0);
	if(resp.status !== '9000')
	    throw '[ERROR] Error loading default key in reader (position' + i + ') : ' + resp.status;

	// Authenticating against sector 1
	var resp = card.authenticateSector(1);
	if(resp.status !== '9000')
	    throw '[ERROR] Error authenticating against sector 1: ' + resp.status;

	var cardNumAndExpiration = card.readBlock(1, 2);
	if (cardNumAndExpiration.status !== '9000')
	    throw '[ERROR] Card error reading card number and card expiration in sector 1 block 2: ' + cardNumAndExpiration.status;

	cardNumAndExpiration = cardNumAndExpiration.data;

	var cardNumberLength = cardNumAndExpiration.byteAt(1);
	var cardNumTLV =  cardNumAndExpiration.left(cardNumberLength + 2);
	var expirationTLV = cardNumAndExpiration.right(16- (cardNumberLength + 2)).left(6);

	var resultChain = priceTLV.concat(datetimeTLV).concat(transactionTLV).concat(stabTLV).concat(cardNumTLV).concat(expirationTLV).concat(petTypeTLV).concat(verifTLV);

	var mac = card.calcMAC(resultChain);
	resultChain = resultChain.concat(mac);

	print('Pay request Sent!!!');

	var result = resultChain.toString(BASE64);
	return result;

    }catch(err){
	print(err);
    }finally{
	card.close();
    }
};

pay(20.25);
