let private_key = utils.randomPrivateKey();
console.log(arrayBufferToBase64(private_key));
document.querySelector("button[type='submit']").addEventListener('click',(e)=>{
    e.preventDefault();
    e.stopImmediatePropagation()
    e.stopPropagation()
    getPublicKeyAsync(private_key).then(
        (public_key)=>{
            signAsync(Uint8Array.from("testing"),private_key)
                .then((signature)=>{
                    fetch("/",{
                        method: "POST", 
                        headers: {
                            "x-sec-private":arrayBufferToBase64(private_key),
                            "X-sec-pubkey":arrayBufferToBase64(public_key),
                            "x-sec-signature":arrayBufferToBase64(signature),
                            "x-sec-content":btoa("testing"),
                            "Content-Type": "text/plain",
                        }, 
                    }
                    )
                    .then((data)=>{
                        console.log("private: ",private_key,"\n",arrayBufferToBase64(private_key));
                        console.log("public: ",public_key,"\n",arrayBufferToBase64(public_key));
                        console.log("signature: ",signature,"\n",arrayBufferToBase64(signature));

                        for (h of data.headers.entries()){
                            console.log(h)
                        }
                        return data.text()})
                })
            }
)});

///////////////////////////////////////////   
//FROM isummation.com 
function arrayBufferToBase64( buffer ) {
	var binary = '';
	var bytes = new Uint8Array( buffer );
	var len = bytes.byteLength;
	for (var i = 0; i < len; i++) {
		binary += String.fromCharCode( bytes[ i ] );
	}
	return window.btoa( binary );
}  
	
function base64ToArrayBuffer(base64) {
    var binary_string =  window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++)        {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}
//////////////////////////////////////////