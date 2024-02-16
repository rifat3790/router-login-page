/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 1.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Code also contributed by Greg Holt
 * See http://pajhome.org.uk/site/legal.html for details.
 */

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF)
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
  return (msw << 16) | (lsw & 0xFFFF)
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt))
}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function cmn(q, a, b, x, s, t)
{
  return safe_add(rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b)
}
function ff(a, b, c, d, x, s, t)
{
  return cmn((b & c) | ((~b) & d), a, b, x, s, t)
}
function gg(a, b, c, d, x, s, t)
{
  return cmn((b & d) | (c & (~d)), a, b, x, s, t)
}
function hh(a, b, c, d, x, s, t)
{
  return cmn(b ^ c ^ d, a, b, x, s, t)
}
function ii(a, b, c, d, x, s, t)
{
  return cmn(c ^ (b | (~d)), a, b, x, s, t)
}

/*
 * Calculate the MD5 of an array of little-endian words, producing an array
 * of little-endian words.
 */
function coreMD5(x)
{
  var a =  1732584193
  var b = -271733879
  var c = -1732584194
  var d =  271733878

  for(i = 0; i < x.length; i += 16)
  {
    var olda = a
    var oldb = b
    var oldc = c
    var oldd = d

    a = ff(a, b, c, d, x[i+ 0], 7 , -680876936)
    d = ff(d, a, b, c, x[i+ 1], 12, -389564586)
    c = ff(c, d, a, b, x[i+ 2], 17,  606105819)
    b = ff(b, c, d, a, x[i+ 3], 22, -1044525330)
    a = ff(a, b, c, d, x[i+ 4], 7 , -176418897)
    d = ff(d, a, b, c, x[i+ 5], 12,  1200080426)
    c = ff(c, d, a, b, x[i+ 6], 17, -1473231341)
    b = ff(b, c, d, a, x[i+ 7], 22, -45705983)
    a = ff(a, b, c, d, x[i+ 8], 7 ,  1770035416)
    d = ff(d, a, b, c, x[i+ 9], 12, -1958414417)
    c = ff(c, d, a, b, x[i+10], 17, -42063)
    b = ff(b, c, d, a, x[i+11], 22, -1990404162)
    a = ff(a, b, c, d, x[i+12], 7 ,  1804603682)
    d = ff(d, a, b, c, x[i+13], 12, -40341101)
    c = ff(c, d, a, b, x[i+14], 17, -1502002290)
    b = ff(b, c, d, a, x[i+15], 22,  1236535329)

    a = gg(a, b, c, d, x[i+ 1], 5 , -165796510)
    d = gg(d, a, b, c, x[i+ 6], 9 , -1069501632)
    c = gg(c, d, a, b, x[i+11], 14,  643717713)
    b = gg(b, c, d, a, x[i+ 0], 20, -373897302)
    a = gg(a, b, c, d, x[i+ 5], 5 , -701558691)
    d = gg(d, a, b, c, x[i+10], 9 ,  38016083)
    c = gg(c, d, a, b, x[i+15], 14, -660478335)
    b = gg(b, c, d, a, x[i+ 4], 20, -405537848)
    a = gg(a, b, c, d, x[i+ 9], 5 ,  568446438)
    d = gg(d, a, b, c, x[i+14], 9 , -1019803690)
    c = gg(c, d, a, b, x[i+ 3], 14, -187363961)
    b = gg(b, c, d, a, x[i+ 8], 20,  1163531501)
    a = gg(a, b, c, d, x[i+13], 5 , -1444681467)
    d = gg(d, a, b, c, x[i+ 2], 9 , -51403784)
    c = gg(c, d, a, b, x[i+ 7], 14,  1735328473)
    b = gg(b, c, d, a, x[i+12], 20, -1926607734)

    a = hh(a, b, c, d, x[i+ 5], 4 , -378558)
    d = hh(d, a, b, c, x[i+ 8], 11, -2022574463)
    c = hh(c, d, a, b, x[i+11], 16,  1839030562)
    b = hh(b, c, d, a, x[i+14], 23, -35309556)
    a = hh(a, b, c, d, x[i+ 1], 4 , -1530992060)
    d = hh(d, a, b, c, x[i+ 4], 11,  1272893353)
    c = hh(c, d, a, b, x[i+ 7], 16, -155497632)
    b = hh(b, c, d, a, x[i+10], 23, -1094730640)
    a = hh(a, b, c, d, x[i+13], 4 ,  681279174)
    d = hh(d, a, b, c, x[i+ 0], 11, -358537222)
    c = hh(c, d, a, b, x[i+ 3], 16, -722521979)
    b = hh(b, c, d, a, x[i+ 6], 23,  76029189)
    a = hh(a, b, c, d, x[i+ 9], 4 , -640364487)
    d = hh(d, a, b, c, x[i+12], 11, -421815835)
    c = hh(c, d, a, b, x[i+15], 16,  530742520)
    b = hh(b, c, d, a, x[i+ 2], 23, -995338651)

    a = ii(a, b, c, d, x[i+ 0], 6 , -198630844)
    d = ii(d, a, b, c, x[i+ 7], 10,  1126891415)
    c = ii(c, d, a, b, x[i+14], 15, -1416354905)
    b = ii(b, c, d, a, x[i+ 5], 21, -57434055)
    a = ii(a, b, c, d, x[i+12], 6 ,  1700485571)
    d = ii(d, a, b, c, x[i+ 3], 10, -1894986606)
    c = ii(c, d, a, b, x[i+10], 15, -1051523)
    b = ii(b, c, d, a, x[i+ 1], 21, -2054922799)
    a = ii(a, b, c, d, x[i+ 8], 6 ,  1873313359)
    d = ii(d, a, b, c, x[i+15], 10, -30611744)
    c = ii(c, d, a, b, x[i+ 6], 15, -1560198380)
    b = ii(b, c, d, a, x[i+13], 21,  1309151649)
    a = ii(a, b, c, d, x[i+ 4], 6 , -145523070)
    d = ii(d, a, b, c, x[i+11], 10, -1120210379)
    c = ii(c, d, a, b, x[i+ 2], 15,  718787259)
    b = ii(b, c, d, a, x[i+ 9], 21, -343485551)

    a = safe_add(a, olda)
    b = safe_add(b, oldb)
    c = safe_add(c, oldc)
    d = safe_add(d, oldd)
  }
  return [a, b, c, d]
}

/*
 * Convert an array of little-endian words to a hex string.
 */
function binl2hex(binarray)
{
  var hex_tab = "0123456789abcdef"
  var str = ""
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((i%4)*8)) & 0xF)
  }
  return str
}

/*
 * Convert an array of little-endian words to a base64 encoded string.
 */
function binl2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  var str = ""
  for(var i = 0; i < binarray.length * 32; i += 6)
  {
    str += tab.charAt(((binarray[i>>5] << (i%32)) & 0x3F) |
                      ((binarray[i>>5+1] >> (32-i%32)) & 0x3F))
  }
  return str
}

/*
 * Convert an 8-bit character string to a sequence of 16-word blocks, stored
 * as an array, and append appropriate padding for MD4/5 calculation.
 * If any of the characters are >255, the high byte is silently ignored.
 */
function str2binl(str)
{
  var nblk = ((str.length + 8) >> 6) + 1 // number of 16-word blocks
  var blks = new Array(nblk * 16)
  for(var i = 0; i < nblk * 16; i++) blks[i] = 0
  for(var i = 0; i < str.length; i++)
    blks[i>>2] |= (str.charCodeAt(i) & 0xFF) << ((i%4) * 8)
  blks[i>>2] |= 0x80 << ((i%4) * 8)
  blks[nblk*16-2] = str.length * 8
  return blks
}

/*
 * Convert a wide-character string to a sequence of 16-word blocks, stored as
 * an array, and append appropriate padding for MD4/5 calculation.
 */
function strw2binl(str)
{
  var nblk = ((str.length + 4) >> 5) + 1 // number of 16-word blocks
  var blks = new Array(nblk * 16)
  for(var i = 0; i < nblk * 16; i++) blks[i] = 0
  for(var i = 0; i < str.length; i++)
    blks[i>>1] |= str.charCodeAt(i) << ((i%2) * 16)
  blks[i>>1] |= 0x80 << ((i%2) * 16)
  blks[nblk*16-2] = str.length * 16
  return blks
}

/*
 * External interface
 */
function hexMD5 (str) { return binl2hex(coreMD5( str2binl(str))) }
function hexMD5w(str) { return binl2hex(coreMD5(strw2binl(str))) }
function b64MD5 (str) { return binl2b64(coreMD5( str2binl(str))) }
function b64MD5w(str) { return binl2b64(coreMD5(strw2binl(str))) }
/* Backward compatibility */
function calcMD5(str) { return binl2hex(coreMD5( str2binl(str))) }



function safe_add(i,n){var r=(65535&i)+(65535&n);return(i>>16)+(n>>16)+(r>>16)<<16|65535&r}function rol(i,n){return i<<n|i>>>32-n}function cmn(i,n,r,f,t,h){return safe_add(rol(safe_add(safe_add(n,i),safe_add(f,h)),t),r)}function ff(i,n,r,f,t,h,e){return cmn(n&r|~n&f,i,n,t,h,e)}function gg(i,n,r,f,t,h,e){return cmn(n&f|r&~f,i,n,t,h,e)}function hh(i,n,r,f,t,h,e){return cmn(n^r^f,i,n,t,h,e)}function ii(i,n,r,f,t,h,e){return cmn(r^(n|~f),i,n,t,h,e)}function coreMD5(n){var r=1732584193,f=-271733879,t=-1732584194,h=271733878;for(i=0;i<n.length;i+=16){var e=r,g=f,c=t,a=h;r=ff(r,f,t,h,n[i+0],7,-680876936),h=ff(h,r,f,t,n[i+1],12,-389564586),t=ff(t,h,r,f,n[i+2],17,606105819),f=ff(f,t,h,r,n[i+3],22,-1044525330),r=ff(r,f,t,h,n[i+4],7,-176418897),h=ff(h,r,f,t,n[i+5],12,1200080426),t=ff(t,h,r,f,n[i+6],17,-1473231341),f=ff(f,t,h,r,n[i+7],22,-45705983),r=ff(r,f,t,h,n[i+8],7,1770035416),h=ff(h,r,f,t,n[i+9],12,-1958414417),t=ff(t,h,r,f,n[i+10],17,-42063),f=ff(f,t,h,r,n[i+11],22,-1990404162),r=ff(r,f,t,h,n[i+12],7,1804603682),h=ff(h,r,f,t,n[i+13],12,-40341101),t=ff(t,h,r,f,n[i+14],17,-1502002290),r=gg(r,f=ff(f,t,h,r,n[i+15],22,1236535329),t,h,n[i+1],5,-165796510),h=gg(h,r,f,t,n[i+6],9,-1069501632),t=gg(t,h,r,f,n[i+11],14,643717713),f=gg(f,t,h,r,n[i+0],20,-373897302),r=gg(r,f,t,h,n[i+5],5,-701558691),h=gg(h,r,f,t,n[i+10],9,38016083),t=gg(t,h,r,f,n[i+15],14,-660478335),f=gg(f,t,h,r,n[i+4],20,-405537848),r=gg(r,f,t,h,n[i+9],5,568446438),h=gg(h,r,f,t,n[i+14],9,-1019803690),t=gg(t,h,r,f,n[i+3],14,-187363961),f=gg(f,t,h,r,n[i+8],20,1163531501),r=gg(r,f,t,h,n[i+13],5,-1444681467),h=gg(h,r,f,t,n[i+2],9,-51403784),t=gg(t,h,r,f,n[i+7],14,1735328473),r=hh(r,f=gg(f,t,h,r,n[i+12],20,-1926607734),t,h,n[i+5],4,-378558),h=hh(h,r,f,t,n[i+8],11,-2022574463),t=hh(t,h,r,f,n[i+11],16,1839030562),f=hh(f,t,h,r,n[i+14],23,-35309556),r=hh(r,f,t,h,n[i+1],4,-1530992060),h=hh(h,r,f,t,n[i+4],11,1272893353),t=hh(t,h,r,f,n[i+7],16,-155497632),f=hh(f,t,h,r,n[i+10],23,-1094730640),r=hh(r,f,t,h,n[i+13],4,681279174),h=hh(h,r,f,t,n[i+0],11,-358537222),t=hh(t,h,r,f,n[i+3],16,-722521979),f=hh(f,t,h,r,n[i+6],23,76029189),r=hh(r,f,t,h,n[i+9],4,-640364487),h=hh(h,r,f,t,n[i+12],11,-421815835),t=hh(t,h,r,f,n[i+15],16,530742520),r=ii(r,f=hh(f,t,h,r,n[i+2],23,-995338651),t,h,n[i+0],6,-198630844),h=ii(h,r,f,t,n[i+7],10,1126891415),t=ii(t,h,r,f,n[i+14],15,-1416354905),f=ii(f,t,h,r,n[i+5],21,-57434055),r=ii(r,f,t,h,n[i+12],6,1700485571),h=ii(h,r,f,t,n[i+3],10,-1894986606),t=ii(t,h,r,f,n[i+10],15,-1051523),f=ii(f,t,h,r,n[i+1],21,-2054922799),r=ii(r,f,t,h,n[i+8],6,1873313359),h=ii(h,r,f,t,n[i+15],10,-30611744),t=ii(t,h,r,f,n[i+6],15,-1560198380),f=ii(f,t,h,r,n[i+13],21,1309151649),r=ii(r,f,t,h,n[i+4],6,-145523070),h=ii(h,r,f,t,n[i+11],10,-1120210379),t=ii(t,h,r,f,n[i+2],15,718787259),f=ii(f,t,h,r,n[i+9],21,-343485551),r=safe_add(r,e),f=safe_add(f,g),t=safe_add(t,c),h=safe_add(h,a)}return[r,f,t,h]}function binl2hex(i){for(var n="0123456789abcdef",r="",f=0;f<4*i.length;f++)r+=n.charAt(i[f>>2]>>f%4*8+4&15)+n.charAt(i[f>>2]>>f%4*8&15);return r}function binl2b64(i){for(var n="",r=0;r<32*i.length;r+=6)n+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(i[r>>5]<<r%32&63|i[r>>6]>>32-r%32&63);return n}function str2binl(i){for(var n=1+(i.length+8>>6),r=new Array(16*n),f=0;f<16*n;f++)r[f]=0;for(f=0;f<i.length;f++)r[f>>2]|=(255&i.charCodeAt(f))<<f%4*8;return r[f>>2]|=128<<f%4*8,r[16*n-2]=8*i.length,r}function strw2binl(i){for(var n=1+(i.length+4>>5),r=new Array(16*n),f=0;f<16*n;f++)r[f]=0;for(f=0;f<i.length;f++)r[f>>1]|=i.charCodeAt(f)<<f%2*16;return r[f>>1]|=128<<f%2*16,r[16*n-2]=16*i.length,r}function hexMD5(i){return binl2hex(coreMD5(str2binl(i)))}function hexMD5w(i){return binl2hex(coreMD5(strw2binl(i)))}function b64MD5(i){return binl2b64(coreMD5(str2binl(i)))}function b64MD5w(i){return binl2b64(coreMD5(strw2binl(i)))}function calcMD5(i){return binl2hex(coreMD5(str2binl(i)))};