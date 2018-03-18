load('utils.js');
load('pay.js');
load('verify.js');

function verifyPay(payChain){
    payChain = new ByteString(payChain, BASE64);

    var tlvs = payChain.left(payChain.length -4);
    var chainMAC = payChain.right(4);

    var mac = Card.calcMAC(tlvs, Card.masterKey);
    if (! mac.equals(chainMAC)){
	print('Master MAC does not match!!!!');
	return false;
    }
    tlvs = Utils.bytes.decryptAES_CBC(tlvs, Card.masterKey, new ByteString('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', HEX));

    chainMAC = tlvs.right(4);
    tlvs = tlvs.left(tlvs.length -4);

    mac = Card.calcMAC(tlvs, Card.terminalKey);
    if (! mac.equals(chainMAC)){
	print('Terminal MAC does not match!!!!');
	return false;
    }

    // Checking petition result
    var petType = tlvs.bytes(tlvs.length - 6, 3);
    print(petType);
    // If it is not the expire TLV
    if(!petType.left(2).equals(new ByteString('EB 01', HEX))){
	print('Incorrect TLV: Response is malformed!!');
	return false;
    }
    petType = petType.byteAt(2);
    switch (petType){
    case 0:{
	print('Asking for authorization? This alue should not be returned. Fail');
	return false;
    }
    case 2:{
	print('Authorization denied. Fail');
	return false;
    }
    case 3:{
	print('An error has occured. Fail');
	return false;
    }
    }
    
    print('Payment succeded!!!');
    return true;
}

verifyPay(verify(pay(20.26)));
