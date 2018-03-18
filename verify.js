load('utils.js');
load('pay.js');
function denyPay(tlvs){
    print('Pago denegado!!');
    var newPetitionTLV = Utils.tlv.createPetitionTypeTLV('authDenied');
    // Remove the verification type TLV
    var verificationTLV = tlvs.right(3);
    tlvs = tlvs.left(tlvs.length -6).concat(newPetitionTLV).concat(verificationTLV);
    return Card.prepareChain(tlvs);
    
}
function acceptPay(tlvs){
    print('Pago aceptado!!');
    var newPetitionTLV = Utils.tlv.createPetitionTypeTLV('authGaranted');
    // Remove the verification type TLV
    var verificationTLV = tlvs.right(3);
    tlvs = tlvs.left(tlvs.length -6).concat(newPetitionTLV).concat(verificationTLV);
    return Card.prepareChain(tlvs);
}

function verify(payChain){
    payChain = new ByteString(payChain, BASE64);

    var tlvs = payChain.left(payChain.length -4);
    var chainMAC = payChain.right(4);

    var mac = Card.calcMAC(tlvs, Card.masterKey);
    if (! mac.equals(chainMAC))
	return denyPay(tlvs);
    print('Adelante!!!');
    tlvs = Utils.bytes.decryptAES_CBC(tlvs, Card.masterKey, new ByteString('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', HEX));

    chainMAC = tlvs.right(4);
    tlvs = tlvs.left(tlvs.length -4);

    mac = Card.calcMAC(tlvs, Card.terminalKey);
    if (! mac.equals(chainMAC))
	return denyPay(tlvs);

    // Checking expiration
    var expire = tlvs.bytes(tlvs.length - 12, 6);
    // If it is not the expire TLV
    if(!expire.left(2).equals(new ByteString('C3 04', HEX)))
	return denyCard(tlvs);
    expire = expire.right(4).toString(ASCII);
    var year = 2000 + parseInt(expire.substring(2, 4));
    var month = parseInt(expire.substring(0, 2)) - 1;
    if(new Date() > new Date(year, month))
	return denyPay();

    //Checking amount
    var amount = tlvs.left(tlvs.byteAt(1) + 2);
    // Cheking it is the right TLV
    if(!amount.left(1).equals(new ByteString('C6', HEX)))
	return denyPay(tlvs);
    amount = amount.right(amount.byteAt(1)).toUnsigned();

    // If the amount is bigger than 20 euros, we deny it
    if(amount > 2000)
	return denyPay();
    return acceptPay(tlvs);
}

verify(pay(15.26));
