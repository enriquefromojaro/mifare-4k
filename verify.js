function verify(payChain){
    payChain = new ByteString(payChain, BASE64);
    print(payChain);

    var tlvs = payChain.left(payChain.length -4);
    var chainMAC = payChain.right(4);

    var mac = new Card().calcMAC(tlvs);
    if (! mac.equals(chainMAC))
	return denyPay(tlvs);
    print('Patata');
}

verify(pay(56.26));
