load('utils.js')
function denyPay(tlvs){
    print('Pago denegado!!')
}

function verify(payChain){
    var card = new Card();
    payChain = new ByteString(payChain, BASE64);
    print(payChain);

    var tlvs = payChain.left(payChain.length -4);
    var chainMAC = payChain.right(4);

    var mac = card.calcMAC(tlvs, card.masterKey);
    if (! mac.equals(chainMAC))
	return denyPay(tlvs);
    print('Adelante!!!');
    tlvs = Utils.bytes.decryptAES_CBC(tlvs, card.masterKey, new ByteString('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', HEX));
    print(tlvs);
   
    chainMAC = tlvs.right(4);
    tlvs = tlvs.left(tlvs.length -4);

    mac = card.calcMAC(tlvs, card.terminalKey);
    if (! mac.equals(chainMAC))
	return denyPay(tlvs);

    // Now we have checked the macs are correct and we have the original data
}

verify(pay(56.26));
