'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var binFileUtils = require('@iden3/binfileutils');
var ffjavascript = require('ffjavascript');
var Blake2b = require('blake2b-wasm');
var readline = require('readline');
var crypto = require('crypto');
var fastFile = require('fastfile');
var circom_runtime = require('circom_runtime');
var r1csfile = require('r1csfile');
var ejs = require('ejs');
var poseidonJs = require('poseidon-js');
require('js-sha3');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

function _interopNamespace(e) {
    if (e && e.__esModule) return e;
    var n = Object.create(null);
    if (e) {
        Object.keys(e).forEach(function (k) {
            if (k !== 'default') {
                var d = Object.getOwnPropertyDescriptor(e, k);
                Object.defineProperty(n, k, d.get ? d : {
                    enumerable: true,
                    get: function () { return e[k]; }
                });
            }
        });
    }
    n["default"] = e;
    return Object.freeze(n);
}

var binFileUtils__namespace = /*#__PURE__*/_interopNamespace(binFileUtils);
var Blake2b__default = /*#__PURE__*/_interopDefaultLegacy(Blake2b);
var readline__default = /*#__PURE__*/_interopDefaultLegacy(readline);
var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var fastFile__namespace = /*#__PURE__*/_interopNamespace(fastFile);
var ejs__default = /*#__PURE__*/_interopDefaultLegacy(ejs);

ffjavascript.Scalar.e("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
ffjavascript.Scalar.e("21888242871839275222246405745257275088548364400416034343698204186575808495617");

const bls12381q = ffjavascript.Scalar.e("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
const bn128q = ffjavascript.Scalar.e("21888242871839275222246405745257275088696311157297823662689037894645226208583");

async function getCurveFromQ(q) {
    let curve;
    if (ffjavascript.Scalar.eq(q, bn128q)) {
        curve = await ffjavascript.buildBn128();
    } else if (ffjavascript.Scalar.eq(q, bls12381q)) {
        curve = await ffjavascript.buildBls12381();
    } else {
        throw new Error(`Curve not supported: ${ffjavascript.Scalar.toString(q)}`);
    }
    return curve;
}

async function getCurveFromName(name) {
    let curve;
    const normName = normalizeName(name);
    if (["BN128", "BN254", "ALTBN128"].indexOf(normName) >= 0) {
        curve = await ffjavascript.buildBn128();
    } else if (["BLS12381"].indexOf(normName) >= 0) {
        curve = await ffjavascript.buildBls12381();
    } else {
        throw new Error(`Curve not supported: ${name}`);
    }
    return curve;

    function normalizeName(n) {
        return n.toUpperCase().match(/[A-Za-z0-9]+/g).join("");
    }

}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/


function log2( V )
{
    return( ( ( V & 0xFFFF0000 ) !== 0 ? ( V &= 0xFFFF0000, 16 ) : 0 ) | ( ( V & 0xFF00FF00 ) !== 0 ? ( V &= 0xFF00FF00, 8 ) : 0 ) | ( ( V & 0xF0F0F0F0 ) !== 0 ? ( V &= 0xF0F0F0F0, 4 ) : 0 ) | ( ( V & 0xCCCCCCCC ) !== 0 ? ( V &= 0xCCCCCCCC, 2 ) : 0 ) | ( ( V & 0xAAAAAAAA ) !== 0 ) );
}


function formatHash(b, title) {
    const a = new DataView(b.buffer, b.byteOffset, b.byteLength);
    let S = "";
    for (let i=0; i<4; i++) {
        if (i>0) S += "\n";
        S += "\t\t";
        for (let j=0; j<4; j++) {
            if (j>0) S += " ";
            S += a.getUint32(i*16+j*4).toString(16).padStart(8, "0");
        }
    }
    if (title) S = title + "\n" + S;
    return S;
}

function hashIsEqual(h1, h2) {
    if (h1.byteLength != h2.byteLength) return false;
    var dv1 = new Int8Array(h1);
    var dv2 = new Int8Array(h2);
    for (var i = 0 ; i != h1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
}

function cloneHasher(h) {
    const ph = h.getPartialHash();
    const res = Blake2b__default["default"](64);
    res.setPartialHash(ph);
    return res;
}

async function sameRatio$2(curve, g1s, g1sx, g2s, g2sx) {
    if (curve.G1.isZero(g1s)) return false;
    if (curve.G1.isZero(g1sx)) return false;
    if (curve.G2.isZero(g2s)) return false;
    if (curve.G2.isZero(g2sx)) return false;
    // return curve.F12.eq(curve.pairing(g1s, g2sx), curve.pairing(g1sx, g2s));
    const res = await curve.pairingEq(g1s, g2sx, curve.G1.neg(g1sx), g2s);
    return res;
}


function askEntropy() {
    if (process.browser) {
        return window.prompt("Enter a random text. (Entropy): ", "");
    } else {
        const rl = readline__default["default"].createInterface({
            input: process.stdin,
            output: process.stdout
        });

        return new Promise((resolve) => {
            rl.question("Enter a random text. (Entropy): ", (input) => resolve(input) );
        });
    }
}

async function getRandomRng(entropy) {
    // Generate a random Rng
    while (!entropy) {
        entropy = await askEntropy();
    }
    const hasher = Blake2b__default["default"](64);
    hasher.update(crypto__default["default"].randomBytes(64));
    const enc = new TextEncoder(); // always utf-8
    hasher.update(enc.encode(entropy));
    const hash = Buffer.from(hasher.digest());

    const seed = [];
    for (let i=0;i<8;i++) {
        seed[i] = hash.readUInt32BE(i*4);
    }
    const rng = new ffjavascript.ChaCha(seed);
    return rng;
}

function rngFromBeaconParams(beaconHash, numIterationsExp) {
    let nIterationsInner;
    let nIterationsOuter;
    if (numIterationsExp<32) {
        nIterationsInner = (1 << numIterationsExp) >>> 0;
        nIterationsOuter = 1;
    } else {
        nIterationsInner = 0x100000000;
        nIterationsOuter = (1 << (numIterationsExp-32)) >>> 0;
    }

    let curHash = beaconHash;
    for (let i=0; i<nIterationsOuter; i++) {
        for (let j=0; j<nIterationsInner; j++) {
            curHash = crypto__default["default"].createHash("sha256").update(curHash).digest();
        }
    }

    const curHashV = new DataView(curHash.buffer, curHash.byteOffset, curHash.byteLength);
    const seed = [];
    for (let i=0; i<8; i++) {
        seed[i] = curHashV.getUint32(i*4, false);
    }

    const rng = new ffjavascript.ChaCha(seed);

    return rng;
}

function hex2ByteArray(s) {
    if (s instanceof Uint8Array) return s;
    if (s.slice(0,2) == "0x") s= s.slice(2);
    return new Uint8Array(s.match(/[\da-f]{2}/gi).map(function (h) {
        return parseInt(h, 16);
    }));
}

function byteArray2hex(byteArray) {
    return Array.prototype.map.call(byteArray, function(byte) {
        return ("0" + (byte & 0xFF).toString(16)).slice(-2);
    }).join("");
}

function stringifyBigIntsWithField(Fr, o) {
    if (o instanceof Uint8Array)  {
        return Fr.toString(o);
    } else if (Array.isArray(o)) {
        return o.map(stringifyBigIntsWithField.bind(null, Fr));
    } else if (typeof o == "object") {
        const res = {};
        const keys = Object.keys(o);
        keys.forEach( (k) => {
            res[k] = stringifyBigIntsWithField(Fr, o[k]);
        });
        return res;
    } else if ((typeof(o) == "bigint") || o.eq !== undefined)  {
        return o.toString(10);
    } else {
        return o;
    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function writeHeader(fd, zkey) {

    // Write the header
    ///////////
    await binFileUtils__namespace.startWriteSection(fd, 1);
    await fd.writeULE32(1); // Groth
    await binFileUtils__namespace.endWriteSection(fd);

    // Write the Groth header section
    ///////////

    const curve = await getCurveFromQ(zkey.q);

    await binFileUtils__namespace.startWriteSection(fd, 2);
    const primeQ = curve.q;
    const n8q = (Math.floor( (ffjavascript.Scalar.bitLength(primeQ) - 1) / 64) +1)*8;

    const primeR = curve.r;
    const n8r = (Math.floor( (ffjavascript.Scalar.bitLength(primeR) - 1) / 64) +1)*8;

    await fd.writeULE32(n8q);
    await binFileUtils__namespace.writeBigInt(fd, primeQ, n8q);
    await fd.writeULE32(n8r);
    await binFileUtils__namespace.writeBigInt(fd, primeR, n8r);
    await fd.writeULE32(zkey.nVars);                         // Total number of bars
    await fd.writeULE32(zkey.nPublic);                       // Total number of public vars (not including ONE)
    await fd.writeULE32(zkey.domainSize);                  // domainSize
    await writeG1(fd, curve, zkey.vk_alpha_1);
    await writeG1(fd, curve, zkey.vk_beta_1);
    await writeG2(fd, curve, zkey.vk_beta_2);
    await writeG2(fd, curve, zkey.vk_gamma_2);
    await writeG1(fd, curve, zkey.vk_delta_1);
    await writeG2(fd, curve, zkey.vk_delta_2);

    await binFileUtils__namespace.endWriteSection(fd);


}

async function writeG1(fd, curve, p) {
    const buff = new Uint8Array(curve.G1.F.n8*2);
    curve.G1.toRprLEM(buff, 0, p);
    await fd.write(buff);
}

async function writeG2(fd, curve, p) {
    const buff = new Uint8Array(curve.G2.F.n8*2);
    curve.G2.toRprLEM(buff, 0, p);
    await fd.write(buff);
}

async function readG1(fd, curve, toObject) {
    const buff = await fd.read(curve.G1.F.n8*2);
    const res = curve.G1.fromRprLEM(buff, 0);
    return toObject ? curve.G1.toObject(res) : res;
}

async function readG2(fd, curve, toObject) {
    const buff = await fd.read(curve.G2.F.n8*2);
    const res = curve.G2.fromRprLEM(buff, 0);
    return toObject ? curve.G2.toObject(res) : res;
}


async function readHeader$1(fd, sections, toObject) {
    // Read Header
    /////////////////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 1);
    const protocolId = await fd.readULE32();
    await binFileUtils__namespace.endReadSection(fd);

    if (protocolId == 1) {
        return await readHeaderGroth16(fd, sections, toObject);
    } else if (protocolId == 2) {
        return await readHeaderPlonk(fd, sections, toObject);
    } else {
        throw new Error("Protocol not supported: ");
    }        
}




async function readHeaderGroth16(fd, sections, toObject) {
    const zkey = {};

    zkey.protocol = "groth16";

    // Read Groth Header
    /////////////////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 2);
    const n8q = await fd.readULE32();
    zkey.n8q = n8q;
    zkey.q = await binFileUtils__namespace.readBigInt(fd, n8q);

    const n8r = await fd.readULE32();
    zkey.n8r = n8r;
    zkey.r = await binFileUtils__namespace.readBigInt(fd, n8r);
    zkey.curve = await getCurveFromQ(zkey.q);
    zkey.nVars = await fd.readULE32();
    zkey.nPublic = await fd.readULE32();
    zkey.domainSize = await fd.readULE32();
    zkey.power = log2(zkey.domainSize);
    zkey.vk_alpha_1 = await readG1(fd, zkey.curve, toObject);
    zkey.vk_beta_1 = await readG1(fd, zkey.curve, toObject);
    zkey.vk_beta_2 = await readG2(fd, zkey.curve, toObject);
    zkey.vk_gamma_2 = await readG2(fd, zkey.curve, toObject);
    zkey.vk_delta_1 = await readG1(fd, zkey.curve, toObject);
    zkey.vk_delta_2 = await readG2(fd, zkey.curve, toObject);
    await binFileUtils__namespace.endReadSection(fd);

    return zkey;

}




async function readHeaderPlonk(fd, sections, toObject) {
    const zkey = {};

    zkey.protocol = "plonk";

    // Read Plonk Header
    /////////////////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 2);
    const n8q = await fd.readULE32();
    zkey.n8q = n8q;
    zkey.q = await binFileUtils__namespace.readBigInt(fd, n8q);

    const n8r = await fd.readULE32();
    zkey.n8r = n8r;
    zkey.r = await binFileUtils__namespace.readBigInt(fd, n8r);
    zkey.curve = await getCurveFromQ(zkey.q);
    zkey.nVars = await fd.readULE32();
    zkey.nPublic = await fd.readULE32();
    zkey.domainSize = await fd.readULE32();
    zkey.power = log2(zkey.domainSize);
    zkey.nAdditions = await fd.readULE32();
    zkey.nConstrains = await fd.readULE32();
    zkey.k1 = await fd.read(n8r);
    zkey.k2 = await fd.read(n8r);

    zkey.Qm = await readG1(fd, zkey.curve, toObject);
    zkey.Ql = await readG1(fd, zkey.curve, toObject);
    zkey.Qr = await readG1(fd, zkey.curve, toObject);
    zkey.Qo = await readG1(fd, zkey.curve, toObject);
    zkey.Qc = await readG1(fd, zkey.curve, toObject);
    zkey.S1 = await readG1(fd, zkey.curve, toObject);
    zkey.S2 = await readG1(fd, zkey.curve, toObject);
    zkey.S3 = await readG1(fd, zkey.curve, toObject);
    zkey.X_2 = await readG2(fd, zkey.curve, toObject);

    await binFileUtils__namespace.endReadSection(fd);

    return zkey;
}

async function readZKey(fileName, toObject) {
    const {fd, sections} = await binFileUtils__namespace.readBinFile(fileName, "zkey", 1);

    const zkey = await readHeader$1(fd, sections, toObject);

    const Fr = new ffjavascript.F1Field(zkey.r);
    const Rr = ffjavascript.Scalar.mod(ffjavascript.Scalar.shl(1, zkey.n8r*8), zkey.r);
    const Rri = Fr.inv(Rr);
    const Rri2 = Fr.mul(Rri, Rri);

    let curve = await getCurveFromQ(zkey.q);

    // Read IC Section
    ///////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 3);
    zkey.IC = [];
    for (let i=0; i<= zkey.nPublic; i++) {
        const P = await readG1(fd, curve, toObject);
        zkey.IC.push(P);
    }
    await binFileUtils__namespace.endReadSection(fd);


    // Read Coefs
    ///////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 4);
    const nCCoefs = await fd.readULE32();
    zkey.ccoefs = [];
    for (let i=0; i<nCCoefs; i++) {
        const m = await fd.readULE32();
        const c = await fd.readULE32();
        const s = await fd.readULE32();
        const v = await readFr2();
        zkey.ccoefs.push({
            matrix: m,
            constraint: c,
            signal: s,
            value: v
        });
    }
    await binFileUtils__namespace.endReadSection(fd);

    // Read A points
    ///////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 5);
    zkey.A = [];
    for (let i=0; i<zkey.nVars; i++) {
        const A = await readG1(fd, curve, toObject);
        zkey.A[i] = A;
    }
    await binFileUtils__namespace.endReadSection(fd);


    // Read B1
    ///////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 6);
    zkey.B1 = [];
    for (let i=0; i<zkey.nVars; i++) {
        const B1 = await readG1(fd, curve, toObject);

        zkey.B1[i] = B1;
    }
    await binFileUtils__namespace.endReadSection(fd);


    // Read B2 points
    ///////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 7);
    zkey.B2 = [];
    for (let i=0; i<zkey.nVars; i++) {
        const B2 = await readG2(fd, curve, toObject);
        zkey.B2[i] = B2;
    }
    await binFileUtils__namespace.endReadSection(fd);


    // Read C points
    ///////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 8);
    zkey.C = [];
    for (let i=zkey.nPublic+1; i<zkey.nVars; i++) {
        const C = await readG1(fd, curve, toObject);

        zkey.C[i] = C;
    }
    await binFileUtils__namespace.endReadSection(fd);


    // Read H points
    ///////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 9);
    zkey.hExps = [];
    for (let i=0; i<zkey.domainSize; i++) {
        const H = await readG1(fd, curve, toObject);
        zkey.hExps.push(H);
    }
    await binFileUtils__namespace.endReadSection(fd);

    await fd.close();

    return zkey;

    async function readFr2(/* toObject */) {
        const n = await binFileUtils__namespace.readBigInt(fd, zkey.n8r);
        return Fr.mul(n, Rri2);
    }

}


async function readContribution$1(fd, curve, toObject) {
    const c = {delta:{}};
    c.deltaAfter = await readG1(fd, curve, toObject);
    c.delta.g1_s = await readG1(fd, curve, toObject);
    c.delta.g1_sx = await readG1(fd, curve, toObject);
    c.delta.g2_spx = await readG2(fd, curve, toObject);
    c.transcript = await fd.read(64);
    c.type = await fd.readULE32();

    const paramLength = await fd.readULE32();
    const curPos = fd.pos;
    let lastType =0;
    while (fd.pos-curPos < paramLength) {
        const buffType = await fd.read(1);
        if (buffType[0]<= lastType) throw new Error("Parameters in the contribution must be sorted");
        lastType = buffType[0];
        if (buffType[0]==1) {     // Name
            const buffLen = await fd.read(1);
            const buffStr = await fd.read(buffLen[0]);
            c.name = new TextDecoder().decode(buffStr);
        } else if (buffType[0]==2) {
            const buffExp = await fd.read(1);
            c.numIterationsExp = buffExp[0];
        } else if (buffType[0]==3) {
            const buffLen = await fd.read(1);
            c.beaconHash = await fd.read(buffLen[0]);
        } else {
            throw new Error("Parameter not recognized");
        }
    }
    if (fd.pos != curPos + paramLength) {
        throw new Error("Parametes do not match");
    }

    return c;
}


async function readMPCParams(fd, curve, sections) {
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 10);
    const res = { contributions: []};
    res.csHash = await fd.read(64);
    const n = await fd.readULE32();
    for (let i=0; i<n; i++) {
        const c = await readContribution$1(fd, curve);
        res.contributions.push(c);
    }
    await binFileUtils__namespace.endReadSection(fd);

    return res;
}

async function writeContribution$1(fd, curve, c) {
    await writeG1(fd, curve, c.deltaAfter);
    await writeG1(fd, curve, c.delta.g1_s);
    await writeG1(fd, curve, c.delta.g1_sx);
    await writeG2(fd, curve, c.delta.g2_spx);
    await fd.write(c.transcript);
    await fd.writeULE32(c.type || 0);

    const params = [];
    if (c.name) {
        params.push(1);      // Param Name
        const nameData = new TextEncoder("utf-8").encode(c.name.substring(0,64));
        params.push(nameData.byteLength);
        for (let i=0; i<nameData.byteLength; i++) params.push(nameData[i]);
    }
    if (c.type == 1) {
        params.push(2);      // Param numIterationsExp
        params.push(c.numIterationsExp);

        params.push(3);      // Beacon Hash
        params.push(c.beaconHash.byteLength);
        for (let i=0; i<c.beaconHash.byteLength; i++) params.push(c.beaconHash[i]);
    }
    if (params.length>0) {
        const paramsBuff = new Uint8Array(params);
        await fd.writeULE32(paramsBuff.byteLength);
        await fd.write(paramsBuff);
    } else {
        await fd.writeULE32(0);
    }

}

async function writeMPCParams(fd, curve, mpcParams) {
    await binFileUtils__namespace.startWriteSection(fd, 10);
    await fd.write(mpcParams.csHash);
    await fd.writeULE32(mpcParams.contributions.length);
    for (let i=0; i<mpcParams.contributions.length; i++) {
        await writeContribution$1(fd, curve,mpcParams.contributions[i]);
    }
    await binFileUtils__namespace.endWriteSection(fd);
}

function hashG1(hasher, curve, p) {
    const buff = new Uint8Array(curve.G1.F.n8*2);
    curve.G1.toRprUncompressed(buff, 0, p);
    hasher.update(buff);
}

function hashG2(hasher,curve, p) {
    const buff = new Uint8Array(curve.G2.F.n8*2);
    curve.G2.toRprUncompressed(buff, 0, p);
    hasher.update(buff);
}

function hashPubKey(hasher, curve, c) {
    hashG1(hasher, curve, c.deltaAfter);
    hashG1(hasher, curve, c.delta.g1_s);
    hashG1(hasher, curve, c.delta.g1_sx);
    hashG2(hasher, curve, c.delta.g2_spx);
    hasher.update(c.transcript);
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/


async function write(fd, witness, prime) {

    await binFileUtils__namespace.startWriteSection(fd, 1);
    const n8 = (Math.floor( (ffjavascript.Scalar.bitLength(prime) - 1) / 64) +1)*8;
    await fd.writeULE32(n8);
    await binFileUtils__namespace.writeBigInt(fd, prime, n8);
    await fd.writeULE32(witness.length);
    await binFileUtils__namespace.endWriteSection(fd);

    await binFileUtils__namespace.startWriteSection(fd, 2);
    for (let i=0; i<witness.length; i++) {
        await binFileUtils__namespace.writeBigInt(fd, witness[i], n8);
    }
    await binFileUtils__namespace.endWriteSection(fd, 2);


}

async function writeBin(fd, witnessBin, prime) {

    await binFileUtils__namespace.startWriteSection(fd, 1);
    const n8 = (Math.floor( (ffjavascript.Scalar.bitLength(prime) - 1) / 64) +1)*8;
    await fd.writeULE32(n8);
    await binFileUtils__namespace.writeBigInt(fd, prime, n8);
    if (witnessBin.byteLength % n8 != 0) {
        throw new Error("Invalid witness length");
    }
    await fd.writeULE32(witnessBin.byteLength / n8);
    await binFileUtils__namespace.endWriteSection(fd);


    await binFileUtils__namespace.startWriteSection(fd, 2);
    await fd.write(witnessBin);
    await binFileUtils__namespace.endWriteSection(fd);

}

async function readHeader(fd, sections) {

    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 1);
    const n8 = await fd.readULE32();
    const q = await binFileUtils__namespace.readBigInt(fd, n8);
    const nWitness = await fd.readULE32();
    await binFileUtils__namespace.endReadSection(fd);

    return {n8, q, nWitness};

}

async function read(fileName) {

    const {fd, sections} = await binFileUtils__namespace.readBinFile(fileName, "wtns", 2);

    const {n8, nWitness} = await readHeader(fd, sections);

    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 2);
    const res = [];
    for (let i=0; i<nWitness; i++) {
        const v = await binFileUtils__namespace.readBigInt(fd, n8);
        res.push(v);
    }
    await binFileUtils__namespace.endReadSection(fd);

    await fd.close();

    return res;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const {stringifyBigInts: stringifyBigInts$2} = ffjavascript.utils;

async function groth16Prove(zkeyFileName, witnessFileName, logger) {
    const {fd: fdWtns, sections: sectionsWtns} = await binFileUtils__namespace.readBinFile(witnessFileName, "wtns", 2, 1<<25, 1<<23);

    const wtns = await readHeader(fdWtns, sectionsWtns);

    const {fd: fdZKey, sections: sectionsZKey} = await binFileUtils__namespace.readBinFile(zkeyFileName, "zkey", 2, 1<<25, 1<<23);

    const zkey = await readHeader$1(fdZKey, sectionsZKey);

    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    if (!ffjavascript.Scalar.eq(zkey.r,  wtns.q)) {
        throw new Error("Curve of the witness does not match the curve of the proving key");
    }

    if (wtns.nWitness != zkey.nVars) {
        throw new Error(`Invalid witness length. Circuit: ${zkey.nVars}, witness: ${wtns.nWitness}`);
    }

    const curve = zkey.curve;
    const Fr = curve.Fr;
    const G1 = curve.G1;
    const G2 = curve.G2;

    const power = log2(zkey.domainSize);

    if (logger) logger.debug("Reading Wtns");
    const buffWitness = await binFileUtils__namespace.readSection(fdWtns, sectionsWtns, 2);
    if (logger) logger.debug("Reading Coeffs");
    const buffCoeffs = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 4);

    if (logger) logger.debug("Building ABC");
    const [buffA_T, buffB_T, buffC_T] = await buildABC1(curve, zkey, buffWitness, buffCoeffs, logger);

    const inc = power == Fr.s ? curve.Fr.shift : curve.Fr.w[power+1];

    const buffA = await Fr.ifft(buffA_T, "", "", logger, "IFFT_A");
    const buffAodd = await Fr.batchApplyKey(buffA, Fr.e(1), inc);
    const buffAodd_T = await Fr.fft(buffAodd, "", "", logger, "FFT_A");

    const buffB = await Fr.ifft(buffB_T, "", "", logger, "IFFT_B");
    const buffBodd = await Fr.batchApplyKey(buffB, Fr.e(1), inc);
    const buffBodd_T = await Fr.fft(buffBodd, "", "", logger, "FFT_B");

    const buffC = await Fr.ifft(buffC_T, "", "", logger, "IFFT_C");
    const buffCodd = await Fr.batchApplyKey(buffC, Fr.e(1), inc);
    const buffCodd_T = await Fr.fft(buffCodd, "", "", logger, "FFT_C");

    if (logger) logger.debug("Join ABC");
    const buffPodd_T = await joinABC(curve, zkey, buffAodd_T, buffBodd_T, buffCodd_T, logger);

    let proof = {};

    if (logger) logger.debug("Reading A Points");
    const buffBasesA = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 5);
    proof.pi_a = await curve.G1.multiExpAffine(buffBasesA, buffWitness, logger, "multiexp A");

    if (logger) logger.debug("Reading B1 Points");
    const buffBasesB1 = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 6);
    let pib1 = await curve.G1.multiExpAffine(buffBasesB1, buffWitness, logger, "multiexp B1");

    if (logger) logger.debug("Reading B2 Points");
    const buffBasesB2 = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 7);
    proof.pi_b = await curve.G2.multiExpAffine(buffBasesB2, buffWitness, logger, "multiexp B2");

    if (logger) logger.debug("Reading C Points");
    const buffBasesC = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 8);
    proof.pi_c = await curve.G1.multiExpAffine(buffBasesC, buffWitness.slice((zkey.nPublic+1)*curve.Fr.n8), logger, "multiexp C");

    if (logger) logger.debug("Reading H Points");
    const buffBasesH = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 9);
    const resH = await curve.G1.multiExpAffine(buffBasesH, buffPodd_T, logger, "multiexp H");

    const r = curve.Fr.random();
    const s = curve.Fr.random();

    proof.pi_a  = G1.add( proof.pi_a, zkey.vk_alpha_1 );
    proof.pi_a  = G1.add( proof.pi_a, G1.timesFr( zkey.vk_delta_1, r ));

    proof.pi_b  = G2.add( proof.pi_b, zkey.vk_beta_2 );
    proof.pi_b  = G2.add( proof.pi_b, G2.timesFr( zkey.vk_delta_2, s ));

    pib1 = G1.add( pib1, zkey.vk_beta_1 );
    pib1 = G1.add( pib1, G1.timesFr( zkey.vk_delta_1, s ));

    proof.pi_c = G1.add(proof.pi_c, resH);


    proof.pi_c  = G1.add( proof.pi_c, G1.timesFr( proof.pi_a, s ));
    proof.pi_c  = G1.add( proof.pi_c, G1.timesFr( pib1, r ));
    proof.pi_c  = G1.add( proof.pi_c, G1.timesFr( zkey.vk_delta_1, Fr.neg(Fr.mul(r,s) )));


    let publicSignals = [];

    for (let i=1; i<= zkey.nPublic; i++) {
        const b = buffWitness.slice(i*Fr.n8, i*Fr.n8+Fr.n8);
        publicSignals.push(ffjavascript.Scalar.fromRprLE(b));
    }

    proof.pi_a = G1.toObject(G1.toAffine(proof.pi_a));
    proof.pi_b = G2.toObject(G2.toAffine(proof.pi_b));
    proof.pi_c = G1.toObject(G1.toAffine(proof.pi_c));

    proof.protocol = "groth16";
    proof.curve = curve.name;

    await fdZKey.close();
    await fdWtns.close();

    proof = stringifyBigInts$2(proof);
    publicSignals = stringifyBigInts$2(publicSignals);

    return {proof, publicSignals};
}


async function buildABC1(curve, zkey, witness, coeffs, logger) {
    const n8 = curve.Fr.n8;
    const sCoef = 4*3 + zkey.n8r;
    const nCoef = (coeffs.byteLength-4) / sCoef;

    const outBuffA = new ffjavascript.BigBuffer(zkey.domainSize * n8);
    const outBuffB = new ffjavascript.BigBuffer(zkey.domainSize * n8);
    const outBuffC = new ffjavascript.BigBuffer(zkey.domainSize * n8);

    const outBuf = [ outBuffA, outBuffB ];
    for (let i=0; i<nCoef; i++) {
        if ((logger)&&(i%1000000 == 0)) logger.debug(`QAP AB: ${i}/${nCoef}`);
        const buffCoef = coeffs.slice(4+i*sCoef, 4+i*sCoef+sCoef);
        const buffCoefV = new DataView(buffCoef.buffer);
        const m= buffCoefV.getUint32(0, true);
        const c= buffCoefV.getUint32(4, true);
        const s= buffCoefV.getUint32(8, true);
        const coef = buffCoef.slice(12, 12+n8);
        outBuf[m].set(
            curve.Fr.add(
                outBuf[m].slice(c*n8, c*n8+n8),
                curve.Fr.mul(coef, witness.slice(s*n8, s*n8+n8))
            ),
            c*n8
        );
    }

    for (let i=0; i<zkey.domainSize; i++) {
        if ((logger)&&(i%1000000 == 0)) logger.debug(`QAP C: ${i}/${zkey.domainSize}`);
        outBuffC.set(
            curve.Fr.mul(
                outBuffA.slice(i*n8, i*n8+n8),
                outBuffB.slice(i*n8, i*n8+n8),
            ),
            i*n8
        );
    }

    return [outBuffA, outBuffB, outBuffC];

}

/*
async function buldABC(curve, zkey, witness, coeffs, logger) {
    const concurrency = curve.tm.concurrency;
    const sCoef = 4*3 + zkey.n8r;

    let getUint32;

    if (coeffs instanceof BigBuffer) {
        const coeffsDV = [];
        const PAGE_LEN = coeffs.buffers[0].length;
        for (let i=0; i< coeffs.buffers.length; i++) {
            coeffsDV.push(new DataView(coeffs.buffers[i].buffer));
        }
        getUint32 = function (pos) {
            return coeffsDV[Math.floor(pos/PAGE_LEN)].getUint32(pos % PAGE_LEN, true);
        };
    } else {
        const coeffsDV = new DataView(coeffs.buffer, coeffs.byteOffset, coeffs.byteLength);
        getUint32 = function (pos) {
            return coeffsDV.getUint32(pos, true);
        };
    }

    const elementsPerChunk = Math.floor(zkey.domainSize/concurrency);
    const promises = [];

    const cutPoints = [];
    for (let i=0; i<concurrency; i++) {
        cutPoints.push( getCutPoint( Math.floor(i*elementsPerChunk) ));
    }
    cutPoints.push(coeffs.byteLength);

    const chunkSize = 2**26;
    for (let s=0 ; s<zkey.nVars ; s+= chunkSize) {
        if (logger) logger.debug(`QAP ${s}: ${s}/${zkey.nVars}`);
        const ns= Math.min(zkey.nVars-s, chunkSize );

        for (let i=0; i<concurrency; i++) {
            let n;
            if (i< concurrency-1) {
                n = elementsPerChunk;
            } else {
                n = zkey.domainSize - i*elementsPerChunk;
            }
            if (n==0) continue;

            const task = [];

            task.push({cmd: "ALLOCSET", var: 0, buff: coeffs.slice(cutPoints[i], cutPoints[i+1])});
            task.push({cmd: "ALLOCSET", var: 1, buff: witness.slice(s*curve.Fr.n8, (s+ns)*curve.Fr.n8)});
            task.push({cmd: "ALLOC", var: 2, len: n*curve.Fr.n8});
            task.push({cmd: "ALLOC", var: 3, len: n*curve.Fr.n8});
            task.push({cmd: "ALLOC", var: 4, len: n*curve.Fr.n8});
            task.push({cmd: "CALL", fnName: "qap_buildABC", params:[
                {var: 0},
                {val: (cutPoints[i+1] - cutPoints[i])/sCoef},
                {var: 1},
                {var: 2},
                {var: 3},
                {var: 4},
                {val: i*elementsPerChunk},
                {val: n},
                {val: s},
                {val: ns}
            ]});
            task.push({cmd: "GET", out: 0, var: 2, len: n*curve.Fr.n8});
            task.push({cmd: "GET", out: 1, var: 3, len: n*curve.Fr.n8});
            task.push({cmd: "GET", out: 2, var: 4, len: n*curve.Fr.n8});
            promises.push(curve.tm.queueAction(task));
        }
    }

    let result = await Promise.all(promises);

    const nGroups = result.length / concurrency;
    if (nGroups>1) {
        const promises2 = [];
        for (let i=0; i<concurrency; i++) {
            const task=[];
            task.push({cmd: "ALLOC", var: 0, len: result[i][0].byteLength});
            task.push({cmd: "ALLOC", var: 1, len: result[i][0].byteLength});
            for (let m=0; m<3; m++) {
                task.push({cmd: "SET", var: 0, buff: result[i][m]});
                for (let s=1; s<nGroups; s++) {
                    task.push({cmd: "SET", var: 1, buff: result[s*concurrency + i][m]});
                    task.push({cmd: "CALL", fnName: "qap_batchAdd", params:[
                        {var: 0},
                        {var: 1},
                        {val: result[i][m].length/curve.Fr.n8},
                        {var: 0}
                    ]});
                }
                task.push({cmd: "GET", out: m, var: 0, len: result[i][m].length});
            }
            promises2.push(curve.tm.queueAction(task));
        }
        result = await Promise.all(promises2);
    }

    const outBuffA = new BigBuffer(zkey.domainSize * curve.Fr.n8);
    const outBuffB = new BigBuffer(zkey.domainSize * curve.Fr.n8);
    const outBuffC = new BigBuffer(zkey.domainSize * curve.Fr.n8);
    let p=0;
    for (let i=0; i<result.length; i++) {
        outBuffA.set(result[i][0], p);
        outBuffB.set(result[i][1], p);
        outBuffC.set(result[i][2], p);
        p += result[i][0].byteLength;
    }

    return [outBuffA, outBuffB, outBuffC];

    function getCutPoint(v) {
        let m = 0;
        let n = getUint32(0);
        while (m < n) {
            var k = Math.floor((n + m) / 2);
            const va = getUint32(4 + k*sCoef + 4);
            if (va > v) {
                n = k - 1;
            } else if (va < v) {
                m = k + 1;
            } else {
                n = k;
            }
        }
        return 4 + m*sCoef;
    }
}
*/

async function joinABC(curve, zkey, a, b, c, logger) {
    const MAX_CHUNK_SIZE = 1 << 22;

    const n8 = curve.Fr.n8;
    const nElements = Math.floor(a.byteLength / curve.Fr.n8);

    const promises = [];

    for (let i=0; i<nElements; i += MAX_CHUNK_SIZE) {
        if (logger) logger.debug(`JoinABC: ${i}/${nElements}`);
        const n= Math.min(nElements - i, MAX_CHUNK_SIZE);

        const task = [];

        const aChunk = a.slice(i*n8, (i + n)*n8 );
        const bChunk = b.slice(i*n8, (i + n)*n8 );
        const cChunk = c.slice(i*n8, (i + n)*n8 );

        task.push({cmd: "ALLOCSET", var: 0, buff: aChunk});
        task.push({cmd: "ALLOCSET", var: 1, buff: bChunk});
        task.push({cmd: "ALLOCSET", var: 2, buff: cChunk});
        task.push({cmd: "ALLOC", var: 3, len: n*n8});
        task.push({cmd: "CALL", fnName: "qap_joinABC", params:[
            {var: 0},
            {var: 1},
            {var: 2},
            {val: n},
            {var: 3},
        ]});
        task.push({cmd: "CALL", fnName: "frm_batchFromMontgomery", params:[
            {var: 3},
            {val: n},
            {var: 3}
        ]});
        task.push({cmd: "GET", out: 0, var: 3, len: n*n8});
        promises.push(curve.tm.queueAction(task));
    }

    const result = await Promise.all(promises);

    let outBuff;
    if (a instanceof ffjavascript.BigBuffer) {
        outBuff = new ffjavascript.BigBuffer(a.byteLength);
    } else {
        outBuff = new Uint8Array(a.byteLength);
    }

    let p=0;
    for (let i=0; i<result.length; i++) {
        outBuff.set(result[i][0], p);
        p += result[i][0].byteLength;
    }

    return outBuff;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const { unstringifyBigInts: unstringifyBigInts$7} = ffjavascript.utils;

async function wtnsCalculate(_input, wasmFileName, wtnsFileName, options) {
    const input = unstringifyBigInts$7(_input);

    const fdWasm = await fastFile__namespace.readExisting(wasmFileName);
    const wasm = await fdWasm.read(fdWasm.totalSize);
    await fdWasm.close();

    const wc = await circom_runtime.WitnessCalculatorBuilder(wasm);
    if (wc.circom_version() == 1) {
        const w = await wc.calculateBinWitness(input);

        const fdWtns = await binFileUtils__namespace.createBinFile(wtnsFileName, "wtns", 2, 2);

        await writeBin(fdWtns, w, wc.prime);
        await fdWtns.close();
    } else {
        const fdWtns = await fastFile__namespace.createOverride(wtnsFileName);

        const w = await wc.calculateWTNSBin(input);

        await fdWtns.write(w);
        await fdWtns.close();
    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const {unstringifyBigInts: unstringifyBigInts$6} = ffjavascript.utils;

async function groth16FullProve(_input, wasmFile, zkeyFileName, logger) {
    const input = unstringifyBigInts$6(_input);

    const wtns= {
        type: "mem"
    };
    await wtnsCalculate(input, wasmFile, wtns);
    return await groth16Prove(zkeyFileName, wtns, logger);
}

/*
    Copyright 2018 0kims association.

    This file is part of snarkjs.

    snarkjs is a free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License as published by the
    Free Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    snarkjs is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    snarkjs. If not, see <https://www.gnu.org/licenses/>.
*/
const {unstringifyBigInts: unstringifyBigInts$5} = ffjavascript.utils;

async function groth16Verify(_vk_verifier, _publicSignals, _proof, logger) {
/*
    let cpub = vk_verifier.IC[0];
    for (let s= 0; s< vk_verifier.nPublic; s++) {
        cpub  = G1.add( cpub, G1.timesScalar( vk_verifier.IC[s+1], publicSignals[s]));
    }
*/

    const vk_verifier = unstringifyBigInts$5(_vk_verifier);
    const proof = unstringifyBigInts$5(_proof);
    const publicSignals = unstringifyBigInts$5(_publicSignals);

    const curve = await getCurveFromName(vk_verifier.curve);

    const IC0 = curve.G1.fromObject(vk_verifier.IC[0]);
    const IC = new Uint8Array(curve.G1.F.n8*2 * publicSignals.length);
    const w = new Uint8Array(curve.Fr.n8 * publicSignals.length);

    for (let i=0; i<publicSignals.length; i++) {
        const buffP = curve.G1.fromObject(vk_verifier.IC[i+1]);
        IC.set(buffP, i*curve.G1.F.n8*2);
        ffjavascript.Scalar.toRprLE(w, curve.Fr.n8*i, publicSignals[i], curve.Fr.n8);
    }

    let cpub = await curve.G1.multiExpAffine(IC, w);
    cpub = curve.G1.add(cpub, IC0);

    const pi_a = curve.G1.fromObject(proof.pi_a);
    const pi_b = curve.G2.fromObject(proof.pi_b);
    const pi_c = curve.G1.fromObject(proof.pi_c);

    const vk_gamma_2 = curve.G2.fromObject(vk_verifier.vk_gamma_2);
    const vk_delta_2 = curve.G2.fromObject(vk_verifier.vk_delta_2);
    const vk_alpha_1 = curve.G1.fromObject(vk_verifier.vk_alpha_1);
    const vk_beta_2 = curve.G2.fromObject(vk_verifier.vk_beta_2);

    const res = await curve.pairingEq(
        curve.G1.neg(pi_a) , pi_b,
        cpub , vk_gamma_2,
        pi_c , vk_delta_2,

        vk_alpha_1, vk_beta_2
    );

    if (! res) {
        if (logger) logger.error("Invalid proof");
        return false;
    }

    if (logger) logger.info("OK!");
    return true;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const { unstringifyBigInts: unstringifyBigInts$4} = ffjavascript.utils;

function p256$1(n) {
    let nstr = n.toString(16);
    while (nstr.length < 64) nstr = "0"+nstr;
    nstr = `"0x${nstr}"`;
    return nstr;
}

async function groth16ExportSolidityCallData(_proof, _pub) {
    const proof = unstringifyBigInts$4(_proof);
    const pub = unstringifyBigInts$4(_pub);

    let inputs = "";
    for (let i=0; i<pub.length; i++) {
        if (inputs != "") inputs = inputs + ",";
        inputs = inputs + p256$1(pub[i]);
    }

    let S;
    S=`[${p256$1(proof.pi_a[0])}, ${p256$1(proof.pi_a[1])}],` +
        `[[${p256$1(proof.pi_b[0][1])}, ${p256$1(proof.pi_b[0][0])}],[${p256$1(proof.pi_b[1][1])}, ${p256$1(proof.pi_b[1][0])}]],` +
        `[${p256$1(proof.pi_c[0])}, ${p256$1(proof.pi_c[1])}],` +
        `[${inputs}]`;

    return S;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

var groth16 = /*#__PURE__*/Object.freeze({
    __proto__: null,
    fullProve: groth16FullProve,
    prove: groth16Prove,
    verify: groth16Verify,
    exportSolidityCallData: groth16ExportSolidityCallData
});

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

function hashToG2(curve, hash) {
    const hashV = new DataView(hash.buffer, hash.byteOffset, hash.byteLength);
    const seed = [];
    for (let i=0; i<8; i++) {
        seed[i] = hashV.getUint32(i*4);
    }

    const rng = new ffjavascript.ChaCha(seed);

    const g2_sp = curve.G2.fromRng(rng);

    return g2_sp;
}

function getG2sp(curve, persinalization, challenge, g1s, g1sx) {

    const h = Blake2b__default["default"](64);
    const b1 = new Uint8Array([persinalization]);
    h.update(b1);
    h.update(challenge);
    const b3 = curve.G1.toUncompressed(g1s);
    h.update( b3);
    const b4 = curve.G1.toUncompressed(g1sx);
    h.update( b4);
    const hash =h.digest();

    return hashToG2(curve, hash);
}

function calculatePubKey(k, curve, personalization, challengeHash, rng ) {
    k.g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
    k.g1_sx = curve.G1.toAffine(curve.G1.timesFr(k.g1_s, k.prvKey));
    k.g2_sp = curve.G2.toAffine(getG2sp(curve, personalization, challengeHash, k.g1_s, k.g1_sx));
    k.g2_spx = curve.G2.toAffine(curve.G2.timesFr(k.g2_sp, k.prvKey));
    return k;
}

function createPTauKey(curve, challengeHash, rng) {
    const key = {
        tau: {},
        alpha: {},
        beta: {}
    };
    key.tau.prvKey = curve.Fr.fromRng(rng);
    key.alpha.prvKey = curve.Fr.fromRng(rng);
    key.beta.prvKey = curve.Fr.fromRng(rng);
    calculatePubKey(key.tau, curve, 0, challengeHash, rng);
    calculatePubKey(key.alpha, curve, 1, challengeHash, rng);
    calculatePubKey(key.beta, curve, 2, challengeHash, rng);
    return key;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function writePTauHeader(fd, curve, power, ceremonyPower) {
    // Write the header
    ///////////

    if (! ceremonyPower) ceremonyPower = power;
    await fd.writeULE32(1); // Header type
    const pHeaderSize = fd.pos;
    await fd.writeULE64(0); // Temporally set to 0 length

    await fd.writeULE32(curve.F1.n64*8);

    const buff = new Uint8Array(curve.F1.n8);
    ffjavascript.Scalar.toRprLE(buff, 0, curve.q, curve.F1.n8);
    await fd.write(buff);
    await fd.writeULE32(power);                    // power
    await fd.writeULE32(ceremonyPower);               // power

    const headerSize = fd.pos - pHeaderSize - 8;

    const oldPos = fd.pos;

    await fd.writeULE64(headerSize, pHeaderSize);

    fd.pos = oldPos;
}

async function readPTauHeader(fd, sections) {
    if (!sections[1])  throw new Error(fd.fileName + ": File has no  header");
    if (sections[1].length>1) throw new Error(fd.fileName +": File has more than one header");

    fd.pos = sections[1][0].p;
    const n8 = await fd.readULE32();
    const buff = await fd.read(n8);
    const q = ffjavascript.Scalar.fromRprLE(buff);

    const curve = await getCurveFromQ(q);

    if (curve.F1.n64*8 != n8) throw new Error(fd.fileName +": Invalid size");

    const power = await fd.readULE32();
    const ceremonyPower = await fd.readULE32();

    if (fd.pos-sections[1][0].p != sections[1][0].size) throw new Error("Invalid PTau header size");

    return {curve, power, ceremonyPower};
}


async function readPtauPubKey(fd, curve, montgomery) {

    const buff = await fd.read(curve.F1.n8*2*6 + curve.F2.n8*2*3);

    return fromPtauPubKeyRpr(buff, 0, curve, montgomery);
}

function fromPtauPubKeyRpr(buff, pos, curve, montgomery) {

    const key = {
        tau: {},
        alpha: {},
        beta: {}
    };

    key.tau.g1_s = readG1();
    key.tau.g1_sx = readG1();
    key.alpha.g1_s = readG1();
    key.alpha.g1_sx = readG1();
    key.beta.g1_s = readG1();
    key.beta.g1_sx = readG1();
    key.tau.g2_spx = readG2();
    key.alpha.g2_spx = readG2();
    key.beta.g2_spx = readG2();

    return key;

    function readG1() {
        let p;
        if (montgomery) {
            p = curve.G1.fromRprLEM( buff, pos );
        } else {
            p = curve.G1.fromRprUncompressed( buff, pos );
        }
        pos += curve.G1.F.n8*2;
        return p;
    }

    function readG2() {
        let p;
        if (montgomery) {
            p = curve.G2.fromRprLEM( buff, pos );
        } else {
            p = curve.G2.fromRprUncompressed( buff, pos );
        }
        pos += curve.G2.F.n8*2;
        return p;
    }
}

function toPtauPubKeyRpr(buff, pos, curve, key, montgomery) {

    writeG1(key.tau.g1_s);
    writeG1(key.tau.g1_sx);
    writeG1(key.alpha.g1_s);
    writeG1(key.alpha.g1_sx);
    writeG1(key.beta.g1_s);
    writeG1(key.beta.g1_sx);
    writeG2(key.tau.g2_spx);
    writeG2(key.alpha.g2_spx);
    writeG2(key.beta.g2_spx);

    async function writeG1(p) {
        if (montgomery) {
            curve.G1.toRprLEM(buff, pos, p);
        } else {
            curve.G1.toRprUncompressed(buff, pos, p);
        }
        pos += curve.F1.n8*2;
    }

    async function writeG2(p) {
        if (montgomery) {
            curve.G2.toRprLEM(buff, pos, p);
        } else {
            curve.G2.toRprUncompressed(buff, pos, p);
        }
        pos += curve.F2.n8*2;
    }

    return buff;
}

async function writePtauPubKey(fd, curve, key, montgomery) {
    const buff = new Uint8Array(curve.F1.n8*2*6 + curve.F2.n8*2*3);
    toPtauPubKeyRpr(buff, 0, curve, key, montgomery);
    await fd.write(buff);
}

async function readContribution(fd, curve) {
    const c = {};

    c.tauG1 = await readG1();
    c.tauG2 = await readG2();
    c.alphaG1 = await readG1();
    c.betaG1 = await readG1();
    c.betaG2 = await readG2();
    c.key = await readPtauPubKey(fd, curve, true);
    c.partialHash = await fd.read(216);
    c.nextChallenge = await fd.read(64);
    c.type = await fd.readULE32();

    const buffV  = new Uint8Array(curve.G1.F.n8*2*6+curve.G2.F.n8*2*3);
    toPtauPubKeyRpr(buffV, 0, curve, c.key, false);

    const responseHasher = Blake2b__default["default"](64);
    responseHasher.setPartialHash(c.partialHash);
    responseHasher.update(buffV);
    c.responseHash = responseHasher.digest();

    const paramLength = await fd.readULE32();
    const curPos = fd.pos;
    let lastType =0;
    while (fd.pos-curPos < paramLength) {
        const buffType = await readDV(1);
        if (buffType[0]<= lastType) throw new Error("Parameters in the contribution must be sorted");
        lastType = buffType[0];
        if (buffType[0]==1) {     // Name
            const buffLen = await readDV(1);
            const buffStr = await readDV(buffLen[0]);
            c.name = new TextDecoder().decode(buffStr);
        } else if (buffType[0]==2) {
            const buffExp = await readDV(1);
            c.numIterationsExp = buffExp[0];
        } else if (buffType[0]==3) {
            const buffLen = await readDV(1);
            c.beaconHash = await readDV(buffLen[0]);
        } else {
            throw new Error("Parameter not recognized");
        }
    }
    if (fd.pos != curPos + paramLength) {
        throw new Error("Parametes do not match");
    }

    return c;

    async function readG1() {
        const pBuff = await fd.read(curve.G1.F.n8*2);
        return curve.G1.fromRprLEM( pBuff );
    }

    async function readG2() {
        const pBuff = await fd.read(curve.G2.F.n8*2);
        return curve.G2.fromRprLEM( pBuff );
    }

    async function readDV(n) {
        const b = await fd.read(n);
        return new Uint8Array(b);
    }
}

async function readContributions(fd, curve, sections) {
    if (!sections[7])  throw new Error(fd.fileName + ": File has no  contributions");
    if (sections[7][0].length>1) throw new Error(fd.fileName +": File has more than one contributions section");

    fd.pos = sections[7][0].p;
    const nContributions = await fd.readULE32();
    const contributions = [];
    for (let i=0; i<nContributions; i++) {
        const c = await readContribution(fd, curve);
        c.id = i+1;
        contributions.push(c);
    }

    if (fd.pos-sections[7][0].p != sections[7][0].size) throw new Error("Invalid contribution section size");

    return contributions;
}

async function writeContribution(fd, curve, contribution) {

    const buffG1 = new Uint8Array(curve.F1.n8*2);
    const buffG2 = new Uint8Array(curve.F2.n8*2);
    await writeG1(contribution.tauG1);
    await writeG2(contribution.tauG2);
    await writeG1(contribution.alphaG1);
    await writeG1(contribution.betaG1);
    await writeG2(contribution.betaG2);
    await writePtauPubKey(fd, curve, contribution.key, true);
    await fd.write(contribution.partialHash);
    await fd.write(contribution.nextChallenge);
    await fd.writeULE32(contribution.type || 0);

    const params = [];
    if (contribution.name) {
        params.push(1);      // Param Name
        const nameData = new TextEncoder("utf-8").encode(contribution.name.substring(0,64));
        params.push(nameData.byteLength);
        for (let i=0; i<nameData.byteLength; i++) params.push(nameData[i]);
    }
    if (contribution.type == 1) {
        params.push(2);      // Param numIterationsExp
        params.push(contribution.numIterationsExp);

        params.push(3);      // Beacon Hash
        params.push(contribution.beaconHash.byteLength);
        for (let i=0; i<contribution.beaconHash.byteLength; i++) params.push(contribution.beaconHash[i]);
    }
    if (params.length>0) {
        const paramsBuff = new Uint8Array(params);
        await fd.writeULE32(paramsBuff.byteLength);
        await fd.write(paramsBuff);
    } else {
        await fd.writeULE32(0);
    }


    async function writeG1(p) {
        curve.G1.toRprLEM(buffG1, 0, p);
        await fd.write(buffG1);
    }

    async function writeG2(p) {
        curve.G2.toRprLEM(buffG2, 0, p);
        await fd.write(buffG2);
    }

}

async function writeContributions(fd, curve, contributions) {

    await fd.writeULE32(7); // Header type
    const pContributionsSize = fd.pos;
    await fd.writeULE64(0); // Temporally set to 0 length

    await fd.writeULE32(contributions.length);
    for (let i=0; i< contributions.length; i++) {
        await writeContribution(fd, curve, contributions[i]);
    }
    const contributionsSize = fd.pos - pContributionsSize - 8;

    const oldPos = fd.pos;

    await fd.writeULE64(contributionsSize, pContributionsSize);
    fd.pos = oldPos;
}

function calculateFirstChallengeHash(curve, power, logger) {
    if (logger) logger.debug("Calculating First Challenge Hash");

    const hasher = new Blake2b__default["default"](64);

    const vG1 = new Uint8Array(curve.G1.F.n8*2);
    const vG2 = new Uint8Array(curve.G2.F.n8*2);
    curve.G1.toRprUncompressed(vG1, 0, curve.G1.g);
    curve.G2.toRprUncompressed(vG2, 0, curve.G2.g);

    hasher.update(Blake2b__default["default"](64).digest());

    let n;

    n=(2 ** power)*2 -1;
    if (logger) logger.debug("Calculate Initial Hash: tauG1");
    hashBlock(vG1, n);
    n= 2 ** power;
    if (logger) logger.debug("Calculate Initial Hash: tauG2");
    hashBlock(vG2, n);
    if (logger) logger.debug("Calculate Initial Hash: alphaTauG1");
    hashBlock(vG1, n);
    if (logger) logger.debug("Calculate Initial Hash: betaTauG1");
    hashBlock(vG1, n);
    hasher.update(vG2);

    return hasher.digest();

    function hashBlock(buff, n) {
        // this block size is a good compromise between speed and the maximum
        // input size of the Blake2b update method (65,535,720 bytes).
        const blockSize = 341000;
        const nBlocks = Math.floor(n / blockSize);
        const rem = n % blockSize;
        const bigBuff = new Uint8Array(blockSize * buff.byteLength);
        for (let i=0; i<blockSize; i++) {
            bigBuff.set(buff, i*buff.byteLength);
        }
        for (let i=0; i<nBlocks; i++) {
            hasher.update(bigBuff);
            if (logger) logger.debug("Initial hash: " +i*blockSize);
        }
        for (let i=0; i<rem; i++) {
            hasher.update(buff);
        }
    }
}


function keyFromBeacon(curve, challengeHash, beaconHash, numIterationsExp) {

    const rng = rngFromBeaconParams(beaconHash, numIterationsExp);

    const key = createPTauKey(curve, challengeHash, rng);

    return key;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function newAccumulator(curve, power, fileName, logger) {

    await Blake2b__default["default"].ready();

    const fd = await binFileUtils__namespace.createBinFile(fileName, "ptau", 1, 7);

    await writePTauHeader(fd, curve, power, 0);

    const buffG1 = curve.G1.oneAffine;
    const buffG2 = curve.G2.oneAffine;

    // Write tauG1
    ///////////
    await binFileUtils__namespace.startWriteSection(fd, 2);
    const nTauG1 = (2 ** power) * 2 -1;
    for (let i=0; i< nTauG1; i++) {
        await fd.write(buffG1);
        if ((logger)&&((i%100000) == 0)&&i) logger.log("tauG1: " + i);
    }
    await binFileUtils__namespace.endWriteSection(fd);

    // Write tauG2
    ///////////
    await binFileUtils__namespace.startWriteSection(fd, 3);
    const nTauG2 = (2 ** power);
    for (let i=0; i< nTauG2; i++) {
        await fd.write(buffG2);
        if ((logger)&&((i%100000) == 0)&&i) logger.log("tauG2: " + i);
    }
    await binFileUtils__namespace.endWriteSection(fd);

    // Write alphaTauG1
    ///////////
    await binFileUtils__namespace.startWriteSection(fd, 4);
    const nAlfaTauG1 = (2 ** power);
    for (let i=0; i< nAlfaTauG1; i++) {
        await fd.write(buffG1);
        if ((logger)&&((i%100000) == 0)&&i) logger.log("alphaTauG1: " + i);
    }
    await binFileUtils__namespace.endWriteSection(fd);

    // Write betaTauG1
    ///////////
    await binFileUtils__namespace.startWriteSection(fd, 5);
    const nBetaTauG1 = (2 ** power);
    for (let i=0; i< nBetaTauG1; i++) {
        await fd.write(buffG1);
        if ((logger)&&((i%100000) == 0)&&i) logger.log("betaTauG1: " + i);
    }
    await binFileUtils__namespace.endWriteSection(fd);

    // Write betaG2
    ///////////
    await binFileUtils__namespace.startWriteSection(fd, 6);
    await fd.write(buffG2);
    await binFileUtils__namespace.endWriteSection(fd);

    // Contributions
    ///////////
    await binFileUtils__namespace.startWriteSection(fd, 7);
    await fd.writeULE32(0); // 0 Contributions
    await binFileUtils__namespace.endWriteSection(fd);

    await fd.close();

    const firstChallengeHash = calculateFirstChallengeHash(curve, power, logger);

    if (logger) logger.debug(formatHash(Blake2b__default["default"](64).digest(), "Blank Contribution Hash:"));

    if (logger) logger.info(formatHash(firstChallengeHash, "First Contribution Hash:"));

    return firstChallengeHash;

}

// Format of the outpu

async function exportChallenge(pTauFilename, challengeFilename, logger) {
    await Blake2b__default["default"].ready();
    const {fd: fdFrom, sections} = await binFileUtils__namespace.readBinFile(pTauFilename, "ptau", 1);

    const {curve, power} = await readPTauHeader(fdFrom, sections);

    const contributions = await readContributions(fdFrom, curve, sections);
    let lastResponseHash, curChallengeHash;
    if (contributions.length == 0) {
        lastResponseHash = Blake2b__default["default"](64).digest();
        curChallengeHash = calculateFirstChallengeHash(curve, power);
    } else {
        lastResponseHash = contributions[contributions.length-1].responseHash;
        curChallengeHash = contributions[contributions.length-1].nextChallenge;
    }

    if (logger) logger.info(formatHash(lastResponseHash, "Last Response Hash: "));

    if (logger) logger.info(formatHash(curChallengeHash, "New Challenge Hash: "));


    const fdTo = await fastFile__namespace.createOverride(challengeFilename);

    const toHash = Blake2b__default["default"](64);
    await fdTo.write(lastResponseHash);
    toHash.update(lastResponseHash);

    await exportSection(2, "G1", (2 ** power) * 2 -1, "tauG1");
    await exportSection(3, "G2", (2 ** power)       , "tauG2");
    await exportSection(4, "G1", (2 ** power)       , "alphaTauG1");
    await exportSection(5, "G1", (2 ** power)       , "betaTauG1");
    await exportSection(6, "G2", 1                  , "betaG2");

    await fdFrom.close();
    await fdTo.close();

    const calcCurChallengeHash = toHash.digest();

    if (!hashIsEqual (curChallengeHash, calcCurChallengeHash)) {
        if (logger) logger.info(formatHash(calcCurChallengeHash, "Calc Curret Challenge Hash: "));

        if (logger) logger.error("PTau file is corrupted. Calculated new challenge hash does not match with the eclared one");
        throw new Error("PTau file is corrupted. Calculated new challenge hash does not match with the eclared one");
    }

    return curChallengeHash;

    async function exportSection(sectionId, groupName, nPoints, sectionName) {
        const G = curve[groupName];
        const sG = G.F.n8*2;
        const nPointsChunk = Math.floor((1<<24)/sG);

        await binFileUtils__namespace.startReadUniqueSection(fdFrom, sections, sectionId);
        for (let i=0; i< nPoints; i+= nPointsChunk) {
            if (logger) logger.debug(`Exporting ${sectionName}: ${i}/${nPoints}`);
            const n = Math.min(nPoints-i, nPointsChunk);
            let buff;
            buff = await fdFrom.read(n*sG);
            buff = await G.batchLEMtoU(buff);
            await fdTo.write(buff);
            toHash.update(buff);
        }
        await binFileUtils__namespace.endReadSection(fdFrom);
    }


}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function importResponse(oldPtauFilename, contributionFilename, newPTauFilename, name, importPoints, logger) {

    await Blake2b__default["default"].ready();

    const noHash = new Uint8Array(64);
    for (let i=0; i<64; i++) noHash[i] = 0xFF;

    const {fd: fdOld, sections} = await binFileUtils__namespace.readBinFile(oldPtauFilename, "ptau", 1);
    const {curve, power} = await readPTauHeader(fdOld, sections);
    const contributions = await readContributions(fdOld, curve, sections);
    const currentContribution = {};

    if (name) currentContribution.name = name;

    const sG1 = curve.F1.n8*2;
    const scG1 = curve.F1.n8; // Compresed size
    const sG2 = curve.F2.n8*2;
    const scG2 = curve.F2.n8; // Compresed size

    const fdResponse = await fastFile__namespace.readExisting(contributionFilename);

    if  (fdResponse.totalSize !=
        64 +                            // Old Hash
        ((2 ** power)*2-1)*scG1 +
        (2 ** power)*scG2 +
        (2 ** power)*scG1 +
        (2 ** power)*scG1 +
        scG2 +
        sG1*6 + sG2*3)
        throw new Error("Size of the contribution is invalid");

    let lastChallengeHash;

    if (contributions.length>0) {
        lastChallengeHash = contributions[contributions.length-1].nextChallenge;
    } else {
        lastChallengeHash = calculateFirstChallengeHash(curve, power, logger);
    }

    const fdNew = await binFileUtils__namespace.createBinFile(newPTauFilename, "ptau", 1, importPoints ? 7: 2);
    await writePTauHeader(fdNew, curve, power);

    const contributionPreviousHash = await fdResponse.read(64);

    if (hashIsEqual(noHash,lastChallengeHash)) {
        lastChallengeHash = contributionPreviousHash;
        contributions[contributions.length-1].nextChallenge = lastChallengeHash;
    }

    if(!hashIsEqual(contributionPreviousHash,lastChallengeHash))
        throw new Error("Wrong contribution. this contribution is not based on the previus hash");

    const hasherResponse = new Blake2b__default["default"](64);
    hasherResponse.update(contributionPreviousHash);

    const startSections = [];
    let res;
    res = await processSection(fdResponse, fdNew, "G1", 2, (2 ** power) * 2 -1, [1], "tauG1");
    currentContribution.tauG1 = res[0];
    res = await processSection(fdResponse, fdNew, "G2", 3, (2 ** power)       , [1], "tauG2");
    currentContribution.tauG2 = res[0];
    res = await processSection(fdResponse, fdNew, "G1", 4, (2 ** power)       , [0], "alphaG1");
    currentContribution.alphaG1 = res[0];
    res = await processSection(fdResponse, fdNew, "G1", 5, (2 ** power)       , [0], "betaG1");
    currentContribution.betaG1 = res[0];
    res = await processSection(fdResponse, fdNew, "G2", 6, 1                  , [0], "betaG2");
    currentContribution.betaG2 = res[0];

    currentContribution.partialHash = hasherResponse.getPartialHash();


    const buffKey = await fdResponse.read(curve.F1.n8*2*6+curve.F2.n8*2*3);

    currentContribution.key = fromPtauPubKeyRpr(buffKey, 0, curve, false);

    hasherResponse.update(new Uint8Array(buffKey));
    const hashResponse = hasherResponse.digest();

    if (logger) logger.info(formatHash(hashResponse, "Contribution Response Hash imported: "));

    if (importPoints) {
        const nextChallengeHasher = new Blake2b__default["default"](64);
        nextChallengeHasher.update(hashResponse);

        await hashSection(nextChallengeHasher, fdNew, "G1", 2, (2 ** power) * 2 -1, "tauG1", logger);
        await hashSection(nextChallengeHasher, fdNew, "G2", 3, (2 ** power)       , "tauG2", logger);
        await hashSection(nextChallengeHasher, fdNew, "G1", 4, (2 ** power)       , "alphaTauG1", logger);
        await hashSection(nextChallengeHasher, fdNew, "G1", 5, (2 ** power)       , "betaTauG1", logger);
        await hashSection(nextChallengeHasher, fdNew, "G2", 6, 1                  , "betaG2", logger);

        currentContribution.nextChallenge = nextChallengeHasher.digest();

        if (logger) logger.info(formatHash(currentContribution.nextChallenge, "Next Challenge Hash: "));
    } else {
        currentContribution.nextChallenge = noHash;
    }

    contributions.push(currentContribution);

    await writeContributions(fdNew, curve, contributions);

    await fdResponse.close();
    await fdNew.close();
    await fdOld.close();

    return currentContribution.nextChallenge;

    async function processSection(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName) {
        if (importPoints) {
            return await processSectionImportPoints(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName);
        } else {
            return await processSectionNoImportPoints(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName);
        }
    }

    async function processSectionImportPoints(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName) {

        const G = curve[groupName];
        const scG = G.F.n8;
        const sG = G.F.n8*2;

        const singularPoints = [];

        await binFileUtils__namespace.startWriteSection(fdTo, sectionId);
        const nPointsChunk = Math.floor((1<<24)/sG);

        startSections[sectionId] = fdTo.pos;

        for (let i=0; i< nPoints; i += nPointsChunk) {
            if (logger) logger.debug(`Importing ${sectionName}: ${i}/${nPoints}`);
            const n = Math.min(nPoints-i, nPointsChunk);

            const buffC = await fdFrom.read(n * scG);
            hasherResponse.update(buffC);

            const buffLEM = await G.batchCtoLEM(buffC);

            await fdTo.write(buffLEM);
            for (let j=0; j<singularPointIndexes.length; j++) {
                const sp = singularPointIndexes[j];
                if ((sp >=i) && (sp < i+n)) {
                    const P = G.fromRprLEM(buffLEM, (sp-i)*sG);
                    singularPoints.push(P);
                }
            }
        }

        await binFileUtils__namespace.endWriteSection(fdTo);

        return singularPoints;
    }


    async function processSectionNoImportPoints(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName) {

        const G = curve[groupName];
        const scG = G.F.n8;

        const singularPoints = [];

        const nPointsChunk = Math.floor((1<<24)/scG);

        for (let i=0; i< nPoints; i += nPointsChunk) {
            if (logger) logger.debug(`Importing ${sectionName}: ${i}/${nPoints}`);
            const n = Math.min(nPoints-i, nPointsChunk);

            const buffC = await fdFrom.read(n * scG);
            hasherResponse.update(buffC);

            for (let j=0; j<singularPointIndexes.length; j++) {
                const sp = singularPointIndexes[j];
                if ((sp >=i) && (sp < i+n)) {
                    const P = G.fromRprCompressed(buffC, (sp-i)*scG);
                    singularPoints.push(P);
                }
            }
        }

        return singularPoints;
    }


    async function hashSection(nextChallengeHasher, fdTo, groupName, sectionId, nPoints, sectionName, logger) {

        const G = curve[groupName];
        const sG = G.F.n8*2;
        const nPointsChunk = Math.floor((1<<24)/sG);

        const oldPos = fdTo.pos;
        fdTo.pos = startSections[sectionId];

        for (let i=0; i< nPoints; i += nPointsChunk) {
            if (logger) logger.debug(`Hashing ${sectionName}: ${i}/${nPoints}`);
            const n = Math.min(nPoints-i, nPointsChunk);

            const buffLEM = await fdTo.read(n * sG);

            const buffU = await G.batchLEMtoU(buffLEM);

            nextChallengeHasher.update(buffU);
        }

        fdTo.pos = oldPos;
    }

}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const sameRatio$1 = sameRatio$2;

async function verifyContribution(curve, cur, prev, logger) {
    let sr;
    if (cur.type == 1) {    // Verify the beacon.
        const beaconKey = keyFromBeacon(curve, prev.nextChallenge, cur.beaconHash, cur.numIterationsExp);

        if (!curve.G1.eq(cur.key.tau.g1_s, beaconKey.tau.g1_s)) {
            if (logger) logger.error(`BEACON key (tauG1_s) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }
        if (!curve.G1.eq(cur.key.tau.g1_sx, beaconKey.tau.g1_sx)) {
            if (logger) logger.error(`BEACON key (tauG1_sx) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }
        if (!curve.G2.eq(cur.key.tau.g2_spx, beaconKey.tau.g2_spx)) {
            if (logger) logger.error(`BEACON key (tauG2_spx) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }

        if (!curve.G1.eq(cur.key.alpha.g1_s, beaconKey.alpha.g1_s)) {
            if (logger) logger.error(`BEACON key (alphaG1_s) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }
        if (!curve.G1.eq(cur.key.alpha.g1_sx, beaconKey.alpha.g1_sx)) {
            if (logger) logger.error(`BEACON key (alphaG1_sx) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }
        if (!curve.G2.eq(cur.key.alpha.g2_spx, beaconKey.alpha.g2_spx)) {
            if (logger) logger.error(`BEACON key (alphaG2_spx) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }

        if (!curve.G1.eq(cur.key.beta.g1_s, beaconKey.beta.g1_s)) {
            if (logger) logger.error(`BEACON key (betaG1_s) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }
        if (!curve.G1.eq(cur.key.beta.g1_sx, beaconKey.beta.g1_sx)) {
            if (logger) logger.error(`BEACON key (betaG1_sx) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }
        if (!curve.G2.eq(cur.key.beta.g2_spx, beaconKey.beta.g2_spx)) {
            if (logger) logger.error(`BEACON key (betaG2_spx) is not generated correctly in challenge #${cur.id}  ${cur.name || ""}` );
            return false;
        }
    }

    cur.key.tau.g2_sp = curve.G2.toAffine(getG2sp(curve, 0, prev.nextChallenge, cur.key.tau.g1_s, cur.key.tau.g1_sx));
    cur.key.alpha.g2_sp = curve.G2.toAffine(getG2sp(curve, 1, prev.nextChallenge, cur.key.alpha.g1_s, cur.key.alpha.g1_sx));
    cur.key.beta.g2_sp = curve.G2.toAffine(getG2sp(curve, 2, prev.nextChallenge, cur.key.beta.g1_s, cur.key.beta.g1_sx));

    sr = await sameRatio$1(curve, cur.key.tau.g1_s, cur.key.tau.g1_sx, cur.key.tau.g2_sp, cur.key.tau.g2_spx);
    if (sr !== true) {
        if (logger) logger.error("INVALID key (tau) in challenge #"+cur.id);
        return false;
    }

    sr = await sameRatio$1(curve, cur.key.alpha.g1_s, cur.key.alpha.g1_sx, cur.key.alpha.g2_sp, cur.key.alpha.g2_spx);
    if (sr !== true) {
        if (logger) logger.error("INVALID key (alpha) in challenge #"+cur.id);
        return false;
    }

    sr = await sameRatio$1(curve, cur.key.beta.g1_s, cur.key.beta.g1_sx, cur.key.beta.g2_sp, cur.key.beta.g2_spx);
    if (sr !== true) {
        if (logger) logger.error("INVALID key (beta) in challenge #"+cur.id);
        return false;
    }

    sr = await sameRatio$1(curve, prev.tauG1, cur.tauG1, cur.key.tau.g2_sp, cur.key.tau.g2_spx);
    if (sr !== true) {
        if (logger) logger.error("INVALID tau*G1. challenge #"+cur.id+" It does not follow the previous contribution");
        return false;
    }

    sr = await sameRatio$1(curve,  cur.key.tau.g1_s, cur.key.tau.g1_sx, prev.tauG2, cur.tauG2);
    if (sr !== true) {
        if (logger) logger.error("INVALID tau*G2. challenge #"+cur.id+" It does not follow the previous contribution");
        return false;
    }

    sr = await sameRatio$1(curve, prev.alphaG1, cur.alphaG1, cur.key.alpha.g2_sp, cur.key.alpha.g2_spx);
    if (sr !== true) {
        if (logger) logger.error("INVALID alpha*G1. challenge #"+cur.id+" It does not follow the previous contribution");
        return false;
    }

    sr = await sameRatio$1(curve, prev.betaG1, cur.betaG1, cur.key.beta.g2_sp, cur.key.beta.g2_spx);
    if (sr !== true) {
        if (logger) logger.error("INVALID beta*G1. challenge #"+cur.id+" It does not follow the previous contribution");
        return false;
    }

    sr = await sameRatio$1(curve,  cur.key.beta.g1_s, cur.key.beta.g1_sx, prev.betaG2, cur.betaG2);
    if (sr !== true) {
        if (logger) logger.error("INVALID beta*G2. challenge #"+cur.id+"It does not follow the previous contribution");
        return false;
    }

    if (logger) logger.info("Powers Of tau file OK!");
    return true;
}

async function verify(tauFilename, logger) {
    let sr;
    await Blake2b__default["default"].ready();

    const {fd, sections} = await binFileUtils__namespace.readBinFile(tauFilename, "ptau", 1);
    const {curve, power, ceremonyPower} = await readPTauHeader(fd, sections);
    const contrs = await readContributions(fd, curve, sections);

    if (logger) logger.debug("power: 2**" + power);
    // Verify Last contribution

    if (logger) logger.debug("Computing initial contribution hash");
    const initialContribution = {
        tauG1: curve.G1.g,
        tauG2: curve.G2.g,
        alphaG1: curve.G1.g,
        betaG1: curve.G1.g,
        betaG2: curve.G2.g,
        nextChallenge: calculateFirstChallengeHash(curve, ceremonyPower, logger),
        responseHash: Blake2b__default["default"](64).digest()
    };

    if (contrs.length == 0) {
        if (logger) logger.error("This file has no contribution! It cannot be used in production");
        return false;
    }

    let prevContr;
    if (contrs.length>1) {
        prevContr = contrs[contrs.length-2];
    } else {
        prevContr = initialContribution;
    }
    const curContr = contrs[contrs.length-1];
    if (logger) logger.debug("Validating contribution #"+contrs[contrs.length-1].id);
    const res = await verifyContribution(curve, curContr, prevContr, logger);
    if (!res) return false;


    const nextContributionHasher = Blake2b__default["default"](64);
    nextContributionHasher.update(curContr.responseHash);

    // Verify powers and compute nextChallengeHash

    // await test();

    // Verify Section tau*G1
    if (logger) logger.debug("Verifying powers in tau*G1 section");
    const rTau1 = await processSection(2, "G1", "tauG1", (2 ** power)*2-1, [0, 1], logger);
    sr = await sameRatio$1(curve, rTau1.R1, rTau1.R2, curve.G2.g, curContr.tauG2);
    if (sr !== true) {
        if (logger) logger.error("tauG1 section. Powers do not match");
        return false;
    }
    if (!curve.G1.eq(curve.G1.g, rTau1.singularPoints[0])) {
        if (logger) logger.error("First element of tau*G1 section must be the generator");
        return false;
    }
    if (!curve.G1.eq(curContr.tauG1, rTau1.singularPoints[1])) {
        if (logger) logger.error("Second element of tau*G1 section does not match the one in the contribution section");
        return false;
    }

    // await test();

    // Verify Section tau*G2
    if (logger) logger.debug("Verifying powers in tau*G2 section");
    const rTau2 = await processSection(3, "G2", "tauG2", 2 ** power, [0, 1],  logger);
    sr = await sameRatio$1(curve, curve.G1.g, curContr.tauG1, rTau2.R1, rTau2.R2);
    if (sr !== true) {
        if (logger) logger.error("tauG2 section. Powers do not match");
        return false;
    }
    if (!curve.G2.eq(curve.G2.g, rTau2.singularPoints[0])) {
        if (logger) logger.error("First element of tau*G2 section must be the generator");
        return false;
    }
    if (!curve.G2.eq(curContr.tauG2, rTau2.singularPoints[1])) {
        if (logger) logger.error("Second element of tau*G2 section does not match the one in the contribution section");
        return false;
    }

    // Verify Section alpha*tau*G1
    if (logger) logger.debug("Verifying powers in alpha*tau*G1 section");
    const rAlphaTauG1 = await processSection(4, "G1", "alphatauG1", 2 ** power, [0], logger);
    sr = await sameRatio$1(curve, rAlphaTauG1.R1, rAlphaTauG1.R2, curve.G2.g, curContr.tauG2);
    if (sr !== true) {
        if (logger) logger.error("alphaTauG1 section. Powers do not match");
        return false;
    }
    if (!curve.G1.eq(curContr.alphaG1, rAlphaTauG1.singularPoints[0])) {
        if (logger) logger.error("First element of alpha*tau*G1 section (alpha*G1) does not match the one in the contribution section");
        return false;
    }

    // Verify Section beta*tau*G1
    if (logger) logger.debug("Verifying powers in beta*tau*G1 section");
    const rBetaTauG1 = await processSection(5, "G1", "betatauG1", 2 ** power, [0], logger);
    sr = await sameRatio$1(curve, rBetaTauG1.R1, rBetaTauG1.R2, curve.G2.g, curContr.tauG2);
    if (sr !== true) {
        if (logger) logger.error("betaTauG1 section. Powers do not match");
        return false;
    }
    if (!curve.G1.eq(curContr.betaG1, rBetaTauG1.singularPoints[0])) {
        if (logger) logger.error("First element of beta*tau*G1 section (beta*G1) does not match the one in the contribution section");
        return false;
    }

    //Verify Beta G2
    const betaG2 = await processSectionBetaG2(logger);
    if (!curve.G2.eq(curContr.betaG2, betaG2)) {
        if (logger) logger.error("betaG2 element in betaG2 section does not match the one in the contribution section");
        return false;
    }


    const nextContributionHash = nextContributionHasher.digest();

    // Check the nextChallengeHash
    if (power == ceremonyPower) {
        if (!hashIsEqual(nextContributionHash,curContr.nextChallenge)) {
            if (logger) logger.error("Hash of the values does not match the next challenge of the last contributor in the contributions section");
            return false;
        }
    }

    if (logger) logger.info(formatHash(nextContributionHash, "Next challenge hash: "));

    // Verify Previous contributions

    printContribution(curContr, prevContr);
    for (let i = contrs.length-2; i>=0; i--) {
        const curContr = contrs[i];
        const prevContr =  (i>0) ? contrs[i-1] : initialContribution;
        const res = await verifyContribution(curve, curContr, prevContr, logger);
        if (!res) return false;
        printContribution(curContr, prevContr);
    }
    if (logger) logger.info("-----------------------------------------------------");

    if ((!sections[12]) || (!sections[13]) || (!sections[14]) || (!sections[15])) {
        if (logger) logger.warn(
            "this file does not contain phase2 precalculated values. Please run: \n" +
            "   snarkjs \"powersoftau preparephase2\" to prepare this file to be used in the phase2 ceremony."
        );
    } else {
        let res;
        res = await verifyLagrangeEvaluations("G1", 2, 12, "tauG1", logger);
        if (!res) return false;
        res = await verifyLagrangeEvaluations("G2", 3, 13, "tauG2", logger);
        if (!res) return false;
        res = await verifyLagrangeEvaluations("G1", 4, 14, "alphaTauG1", logger);
        if (!res) return false;
        res = await verifyLagrangeEvaluations("G1", 5, 15, "betaTauG1", logger);
        if (!res) return false;
    }

    await fd.close();

    if (logger) logger.info("Powers of Tau Ok!");

    return true;

    function printContribution(curContr, prevContr) {
        if (!logger) return;
        logger.info("-----------------------------------------------------");
        logger.info(`Contribution #${curContr.id}: ${curContr.name ||""}`);

        logger.info(formatHash(curContr.nextChallenge, "Next Challenge: "));

        const buffV  = new Uint8Array(curve.G1.F.n8*2*6+curve.G2.F.n8*2*3);
        toPtauPubKeyRpr(buffV, 0, curve, curContr.key, false);

        const responseHasher = Blake2b__default["default"](64);
        responseHasher.setPartialHash(curContr.partialHash);
        responseHasher.update(buffV);
        const responseHash = responseHasher.digest();

        logger.info(formatHash(responseHash, "Response Hash:"));

        logger.info(formatHash(prevContr.nextChallenge, "Response Hash:"));

        if (curContr.type == 1) {
            logger.info(`Beacon generator: ${byteArray2hex(curContr.beaconHash)}`);
            logger.info(`Beacon iterations Exp: ${curContr.numIterationsExp}`);
        }

    }

    async function processSectionBetaG2(logger) {
        const G = curve.G2;
        const sG = G.F.n8*2;
        const buffUv = new Uint8Array(sG);

        if (!sections[6])  {
            logger.error("File has no BetaG2 section");
            throw new Error("File has no BetaG2 section");
        }
        if (sections[6].length>1) {
            logger.error("File has no BetaG2 section");
            throw new Error("File has more than one GetaG2 section");
        }
        fd.pos = sections[6][0].p;

        const buff = await fd.read(sG);
        const P = G.fromRprLEM(buff);

        G.toRprUncompressed(buffUv, 0, P);
        nextContributionHasher.update(buffUv);

        return P;
    }

    async function processSection(idSection, groupName, sectionName, nPoints, singularPointIndexes, logger) {
        const MAX_CHUNK_SIZE = 1<<16;
        const G = curve[groupName];
        const sG = G.F.n8*2;
        await binFileUtils__namespace.startReadUniqueSection(fd, sections, idSection);

        const singularPoints = [];

        let R1 = G.zero;
        let R2 = G.zero;

        let lastBase = G.zero;

        for (let i=0; i<nPoints; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`points relations: ${sectionName}: ${i}/${nPoints} `);
            const n = Math.min(nPoints - i, MAX_CHUNK_SIZE);
            const bases = await fd.read(n*sG);

            const basesU = await G.batchLEMtoU(bases);
            nextContributionHasher.update(basesU);

            const scalars = new Uint8Array(4*(n-1));
            crypto__default["default"].randomFillSync(scalars);


            if (i>0) {
                const firstBase = G.fromRprLEM(bases, 0);
                const r = crypto__default["default"].randomBytes(4).readUInt32BE(0, true);

                R1 = G.add(R1, G.timesScalar(lastBase, r));
                R2 = G.add(R2, G.timesScalar(firstBase, r));
            }

            const r1 = await G.multiExpAffine(bases.slice(0, (n-1)*sG), scalars);
            const r2 = await G.multiExpAffine(bases.slice(sG), scalars);

            R1 = G.add(R1, r1);
            R2 = G.add(R2, r2);

            lastBase = G.fromRprLEM( bases, (n-1)*sG);

            for (let j=0; j<singularPointIndexes.length; j++) {
                const sp = singularPointIndexes[j];
                if ((sp >=i) && (sp < i+n)) {
                    const P = G.fromRprLEM(bases, (sp-i)*sG);
                    singularPoints.push(P);
                }
            }

        }
        await binFileUtils__namespace.endReadSection(fd);

        return {
            R1: R1,
            R2: R2,
            singularPoints: singularPoints
        };

    }

    async function verifyLagrangeEvaluations(gName, tauSection, lagrangeSection, sectionName, logger) {

        if (logger) logger.debug(`Verifying phase2 calculated values ${sectionName}...`);
        const G = curve[gName];
        const sG = G.F.n8*2;

        const seed= new Array(8);
        for (let i=0; i<8; i++) {
            seed[i] = crypto__default["default"].randomBytes(4).readUInt32BE(0, true);
        }

        for (let p=0; p<= power; p ++) {
            const res = await verifyPower(p);
            if (!res) return false;
        }

        if (tauSection == 2) {
            const res = await verifyPower(power+1);
            if (!res) return false;
        }

        return true;

        async function verifyPower(p) {
            if (logger) logger.debug(`Power ${p}...`);
            const n8r = curve.Fr.n8;
            const nPoints = 2 ** p;
            let buff_r = new Uint32Array(nPoints);
            let buffG;

            let rng = new ffjavascript.ChaCha(seed);

            if (logger) logger.debug(`Creating random numbers Powers${p}...`);
            for (let i=0; i<nPoints; i++) {
                if ((p == power+1)&&(i == nPoints-1)) {
                    buff_r[i] = 0;
                } else {
                    buff_r[i] = rng.nextU32();
                }
            }

            buff_r = new Uint8Array(buff_r.buffer, buff_r.byteOffset, buff_r.byteLength);

            if (logger) logger.debug(`reading points Powers${p}...`);
            await binFileUtils__namespace.startReadUniqueSection(fd, sections, tauSection);
            buffG = new ffjavascript.BigBuffer(nPoints*sG);
            if (p == power+1) {
                await fd.readToBuffer(buffG, 0, (nPoints-1)*sG);
                buffG.set(curve.G1.zeroAffine, (nPoints-1)*sG);
            } else {
                await fd.readToBuffer(buffG, 0, nPoints*sG);
            }
            await binFileUtils__namespace.endReadSection(fd, true);

            const resTau = await G.multiExpAffine(buffG, buff_r, logger, sectionName + "_" + p);

            buff_r = new ffjavascript.BigBuffer(nPoints * n8r);

            rng = new ffjavascript.ChaCha(seed);

            const buff4 = new Uint8Array(4);
            const buff4V = new DataView(buff4.buffer);

            if (logger) logger.debug(`Creating random numbers Powers${p}...`);
            for (let i=0; i<nPoints; i++) {
                if ((i != nPoints-1) || (p != power+1)) {
                    buff4V.setUint32(0, rng.nextU32(), true);
                    buff_r.set(buff4, i*n8r);
                }
            }

            if (logger) logger.debug(`batchToMontgomery ${p}...`);
            buff_r = await curve.Fr.batchToMontgomery(buff_r);
            if (logger) logger.debug(`fft ${p}...`);
            buff_r = await curve.Fr.fft(buff_r);
            if (logger) logger.debug(`batchFromMontgomery ${p}...`);
            buff_r = await curve.Fr.batchFromMontgomery(buff_r);

            if (logger) logger.debug(`reading points Lagrange${p}...`);
            await binFileUtils__namespace.startReadUniqueSection(fd, sections, lagrangeSection);
            fd.pos += sG*((2 ** p)-1);
            await fd.readToBuffer(buffG, 0, nPoints*sG);
            await binFileUtils__namespace.endReadSection(fd, true);

            const resLagrange = await G.multiExpAffine(buffG, buff_r, logger, sectionName + "_" + p + "_transformed");

            if (!G.eq(resTau, resLagrange)) {
                if (logger) logger.error("Phase2 caclutation does not match with powers of tau");
                return false;
            }

            return true;
        }
    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

/*
    This function creates a new section in the fdTo file with id idSection.
    It multiplies the pooints in fdFrom by first, first*inc, first*inc^2, ....
    nPoint Times.
    It also updates the newChallengeHasher with the new points
*/

async function applyKeyToSection(fdOld, sections, fdNew, idSection, curve, groupName, first, inc, sectionName, logger) {
    const MAX_CHUNK_SIZE = 1 << 16;
    const G = curve[groupName];
    const sG = G.F.n8*2;
    const nPoints = sections[idSection][0].size / sG;

    await binFileUtils__namespace.startReadUniqueSection(fdOld, sections,idSection );
    await binFileUtils__namespace.startWriteSection(fdNew, idSection);

    let t = first;
    for (let i=0; i<nPoints; i += MAX_CHUNK_SIZE) {
        if (logger) logger.debug(`Applying key: ${sectionName}: ${i}/${nPoints}`);
        const n= Math.min(nPoints - i, MAX_CHUNK_SIZE);
        let buff;
        buff = await fdOld.read(n*sG);
        buff = await G.batchApplyKey(buff, t, inc);
        await fdNew.write(buff);
        t = curve.Fr.mul(t, curve.Fr.exp(inc, n));
    }

    await binFileUtils__namespace.endWriteSection(fdNew);
    await binFileUtils__namespace.endReadSection(fdOld);
}



async function applyKeyToChallengeSection(fdOld, fdNew, responseHasher, curve, groupName, nPoints, first, inc, formatOut, sectionName, logger) {
    const G = curve[groupName];
    const sG = G.F.n8*2;
    const chunkSize = Math.floor((1<<20) / sG);   // 128Mb chunks
    let t = first;
    for (let i=0 ; i<nPoints ; i+= chunkSize) {
        if (logger) logger.debug(`Applying key ${sectionName}: ${i}/${nPoints}`);
        const n= Math.min(nPoints-i, chunkSize );
        const buffInU = await fdOld.read(n * sG);
        const buffInLEM = await G.batchUtoLEM(buffInU);
        const buffOutLEM = await G.batchApplyKey(buffInLEM, t, inc);
        let buffOut;
        if (formatOut == "COMPRESSED") {
            buffOut = await G.batchLEMtoC(buffOutLEM);
        } else {
            buffOut = await G.batchLEMtoU(buffOutLEM);
        }

        if (responseHasher) responseHasher.update(buffOut);
        await fdNew.write(buffOut);
        t = curve.Fr.mul(t, curve.Fr.exp(inc, n));
    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function challengeContribute(curve, challengeFilename, responesFileName, entropy, logger) {
    await Blake2b__default["default"].ready();

    const fdFrom = await fastFile__namespace.readExisting(challengeFilename);


    const sG1 = curve.F1.n64*8*2;
    const sG2 = curve.F2.n64*8*2;
    const domainSize = (fdFrom.totalSize + sG1 - 64 - sG2) / (4*sG1 + sG2);
    let e = domainSize;
    let power = 0;
    while (e>1) {
        e = e /2;
        power += 1;
    }

    if (2 ** power != domainSize) throw new Error("Invalid file size");
    if (logger) logger.debug("Power to tau size: "+power);

    const rng = await getRandomRng(entropy);

    const fdTo = await fastFile__namespace.createOverride(responesFileName);

    // Calculate the hash
    const challengeHasher = Blake2b__default["default"](64);
    for (let i=0; i<fdFrom.totalSize; i+= fdFrom.pageSize) {
        if (logger) logger.debug(`Hashing challenge ${i}/${fdFrom.totalSize}`);
        const s = Math.min(fdFrom.totalSize - i, fdFrom.pageSize);
        const buff = await fdFrom.read(s);
        challengeHasher.update(buff);
    }

    const claimedHash = await fdFrom.read(64, 0);
    if (logger) logger.info(formatHash(claimedHash, "Claimed Previous Response Hash: "));

    const challengeHash = challengeHasher.digest();
    if (logger) logger.info(formatHash(challengeHash, "Current Challenge Hash: "));

    const key = createPTauKey(curve, challengeHash, rng);

    if (logger) {
        ["tau", "alpha", "beta"].forEach( (k) => {
            logger.debug(k + ".g1_s: " + curve.G1.toString(key[k].g1_s, 16));
            logger.debug(k + ".g1_sx: " + curve.G1.toString(key[k].g1_sx, 16));
            logger.debug(k + ".g2_sp: " + curve.G2.toString(key[k].g2_sp, 16));
            logger.debug(k + ".g2_spx: " + curve.G2.toString(key[k].g2_spx, 16));
            logger.debug("");
        });
    }

    const responseHasher = Blake2b__default["default"](64);

    await fdTo.write(challengeHash);
    responseHasher.update(challengeHash);

    await applyKeyToChallengeSection(fdFrom, fdTo, responseHasher, curve, "G1", (2 ** power)*2-1, curve.Fr.one    , key.tau.prvKey, "COMPRESSED", "tauG1"     , logger );
    await applyKeyToChallengeSection(fdFrom, fdTo, responseHasher, curve, "G2", (2 ** power)    , curve.Fr.one    , key.tau.prvKey, "COMPRESSED", "tauG2"     , logger );
    await applyKeyToChallengeSection(fdFrom, fdTo, responseHasher, curve, "G1", (2 ** power)    , key.alpha.prvKey, key.tau.prvKey, "COMPRESSED", "alphaTauG1", logger );
    await applyKeyToChallengeSection(fdFrom, fdTo, responseHasher, curve, "G1", (2 ** power)    , key.beta.prvKey , key.tau.prvKey, "COMPRESSED", "betaTauG1" , logger );
    await applyKeyToChallengeSection(fdFrom, fdTo, responseHasher, curve, "G2", 1             , key.beta.prvKey , key.tau.prvKey, "COMPRESSED", "betaTauG2" , logger );

    // Write and hash key
    const buffKey = new Uint8Array(curve.F1.n8*2*6+curve.F2.n8*2*3);
    toPtauPubKeyRpr(buffKey, 0, curve, key, false);
    await fdTo.write(buffKey);
    responseHasher.update(buffKey);
    const responseHash = responseHasher.digest();
    if (logger) logger.info(formatHash(responseHash, "Contribution Response Hash: "));

    await fdTo.close();
    await fdFrom.close();
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function beacon$1(oldPtauFilename, newPTauFilename, name,  beaconHashStr,numIterationsExp, logger) {
    const beaconHash = hex2ByteArray(beaconHashStr);
    if (   (beaconHash.byteLength == 0)
        || (beaconHash.byteLength*2 !=beaconHashStr.length))
    {
        if (logger) logger.error("Invalid Beacon Hash. (It must be a valid hexadecimal sequence)");
        return false;
    }
    if (beaconHash.length>=256) {
        if (logger) logger.error("Maximum lenght of beacon hash is 255 bytes");
        return false;
    }

    numIterationsExp = parseInt(numIterationsExp);
    if ((numIterationsExp<10)||(numIterationsExp>63)) {
        if (logger) logger.error("Invalid numIterationsExp. (Must be between 10 and 63)");
        return false;
    }


    await Blake2b__default["default"].ready();

    const {fd: fdOld, sections} = await binFileUtils__namespace.readBinFile(oldPtauFilename, "ptau", 1);
    const {curve, power, ceremonyPower} = await readPTauHeader(fdOld, sections);
    if (power != ceremonyPower) {
        if (logger) logger.error("This file has been reduced. You cannot contribute into a reduced file.");
        return false;
    }
    if (sections[12]) {
        if (logger) logger.warn("Contributing into a file that has phase2 calculated. You will have to prepare phase2 again.");
    }
    const contributions = await readContributions(fdOld, curve, sections);
    const curContribution = {
        name: name,
        type: 1, // Beacon
        numIterationsExp: numIterationsExp,
        beaconHash: beaconHash
    };

    let lastChallengeHash;

    if (contributions.length>0) {
        lastChallengeHash = contributions[contributions.length-1].nextChallenge;
    } else {
        lastChallengeHash = calculateFirstChallengeHash(curve, power, logger);
    }

    curContribution.key = keyFromBeacon(curve, lastChallengeHash, beaconHash, numIterationsExp);

    const responseHasher = new Blake2b__default["default"](64);
    responseHasher.update(lastChallengeHash);

    const fdNew = await binFileUtils__namespace.createBinFile(newPTauFilename, "ptau", 1, 7);
    await writePTauHeader(fdNew, curve, power);

    const startSections = [];

    let firstPoints;
    firstPoints = await processSection(2, "G1",  (2 ** power) * 2 -1, curve.Fr.e(1), curContribution.key.tau.prvKey, "tauG1", logger );
    curContribution.tauG1 = firstPoints[1];
    firstPoints = await processSection(3, "G2",  (2 ** power) , curve.Fr.e(1), curContribution.key.tau.prvKey, "tauG2", logger );
    curContribution.tauG2 = firstPoints[1];
    firstPoints = await processSection(4, "G1",  (2 ** power) , curContribution.key.alpha.prvKey, curContribution.key.tau.prvKey, "alphaTauG1", logger );
    curContribution.alphaG1 = firstPoints[0];
    firstPoints = await processSection(5, "G1",  (2 ** power) , curContribution.key.beta.prvKey, curContribution.key.tau.prvKey, "betaTauG1", logger );
    curContribution.betaG1 = firstPoints[0];
    firstPoints = await processSection(6, "G2",  1, curContribution.key.beta.prvKey, curContribution.key.tau.prvKey, "betaTauG2", logger );
    curContribution.betaG2 = firstPoints[0];

    curContribution.partialHash = responseHasher.getPartialHash();

    const buffKey = new Uint8Array(curve.F1.n8*2*6+curve.F2.n8*2*3);

    toPtauPubKeyRpr(buffKey, 0, curve, curContribution.key, false);

    responseHasher.update(new Uint8Array(buffKey));
    const hashResponse = responseHasher.digest();

    if (logger) logger.info(formatHash(hashResponse, "Contribution Response Hash imported: "));

    const nextChallengeHasher = new Blake2b__default["default"](64);
    nextChallengeHasher.update(hashResponse);

    await hashSection(fdNew, "G1", 2, (2 ** power) * 2 -1, "tauG1", logger);
    await hashSection(fdNew, "G2", 3, (2 ** power)       , "tauG2", logger);
    await hashSection(fdNew, "G1", 4, (2 ** power)       , "alphaTauG1", logger);
    await hashSection(fdNew, "G1", 5, (2 ** power)       , "betaTauG1", logger);
    await hashSection(fdNew, "G2", 6, 1                  , "betaG2", logger);

    curContribution.nextChallenge = nextChallengeHasher.digest();

    if (logger) logger.info(formatHash(curContribution.nextChallenge, "Next Challenge Hash: "));

    contributions.push(curContribution);

    await writeContributions(fdNew, curve, contributions);

    await fdOld.close();
    await fdNew.close();

    return hashResponse;

    async function processSection(sectionId, groupName, NPoints, first, inc, sectionName, logger) {
        const res = [];
        fdOld.pos = sections[sectionId][0].p;

        await binFileUtils__namespace.startWriteSection(fdNew, sectionId);

        startSections[sectionId] = fdNew.pos;

        const G = curve[groupName];
        const sG = G.F.n8*2;
        const chunkSize = Math.floor((1<<20) / sG);   // 128Mb chunks
        let t = first;
        for (let i=0 ; i<NPoints ; i+= chunkSize) {
            if (logger) logger.debug(`applying key${sectionName}: ${i}/${NPoints}`);
            const n= Math.min(NPoints-i, chunkSize );
            const buffIn = await fdOld.read(n * sG);
            const buffOutLEM = await G.batchApplyKey(buffIn, t, inc);

            /* Code to test the case where we don't have the 2^m-2 component
            if (sectionName== "tauG1") {
                const bz = new Uint8Array(64);
                buffOutLEM.set(bz, 64*((2 ** power) - 1 ));
            }
            */

            const promiseWrite = fdNew.write(buffOutLEM);
            const buffOutC = await G.batchLEMtoC(buffOutLEM);

            responseHasher.update(buffOutC);
            await promiseWrite;
            if (i==0)   // Return the 2 first points.
                for (let j=0; j<Math.min(2, NPoints); j++)
                    res.push(G.fromRprLEM(buffOutLEM, j*sG));
            t = curve.Fr.mul(t, curve.Fr.exp(inc, n));
        }

        await binFileUtils__namespace.endWriteSection(fdNew);

        return res;
    }


    async function hashSection(fdTo, groupName, sectionId, nPoints, sectionName, logger) {

        const G = curve[groupName];
        const sG = G.F.n8*2;
        const nPointsChunk = Math.floor((1<<24)/sG);

        const oldPos = fdTo.pos;
        fdTo.pos = startSections[sectionId];

        for (let i=0; i< nPoints; i += nPointsChunk) {
            if (logger) logger.debug(`Hashing ${sectionName}: ${i}/${nPoints}`);
            const n = Math.min(nPoints-i, nPointsChunk);

            const buffLEM = await fdTo.read(n * sG);

            const buffU = await G.batchLEMtoU(buffLEM);

            nextChallengeHasher.update(buffU);
        }

        fdTo.pos = oldPos;
    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function contribute(oldPtauFilename, newPTauFilename, name, entropy, logger) {
    await Blake2b__default["default"].ready();

    const {fd: fdOld, sections} = await binFileUtils__namespace.readBinFile(oldPtauFilename, "ptau", 1);
    const {curve, power, ceremonyPower} = await readPTauHeader(fdOld, sections);
    if (power != ceremonyPower) {
        if (logger) logger.error("This file has been reduced. You cannot contribute into a reduced file.");
        throw new Error("This file has been reduced. You cannot contribute into a reduced file.");
    }
    if (sections[12]) {
        if (logger) logger.warn("WARNING: Contributing into a file that has phase2 calculated. You will have to prepare phase2 again.");
    }
    const contributions = await readContributions(fdOld, curve, sections);
    const curContribution = {
        name: name,
        type: 0, // Beacon
    };

    let lastChallengeHash;

    const rng = await getRandomRng(entropy);

    if (contributions.length>0) {
        lastChallengeHash = contributions[contributions.length-1].nextChallenge;
    } else {
        lastChallengeHash = calculateFirstChallengeHash(curve, power, logger);
    }

    // Generate a random key


    curContribution.key = createPTauKey(curve, lastChallengeHash, rng);


    const responseHasher = new Blake2b__default["default"](64);
    responseHasher.update(lastChallengeHash);

    const fdNew = await binFileUtils__namespace.createBinFile(newPTauFilename, "ptau", 1, 7);
    await writePTauHeader(fdNew, curve, power);

    const startSections = [];

    let firstPoints;
    firstPoints = await processSection(2, "G1",  (2 ** power) * 2 -1, curve.Fr.e(1), curContribution.key.tau.prvKey, "tauG1" );
    curContribution.tauG1 = firstPoints[1];
    firstPoints = await processSection(3, "G2",  (2 ** power) , curve.Fr.e(1), curContribution.key.tau.prvKey, "tauG2" );
    curContribution.tauG2 = firstPoints[1];
    firstPoints = await processSection(4, "G1",  (2 ** power) , curContribution.key.alpha.prvKey, curContribution.key.tau.prvKey, "alphaTauG1" );
    curContribution.alphaG1 = firstPoints[0];
    firstPoints = await processSection(5, "G1",  (2 ** power) , curContribution.key.beta.prvKey, curContribution.key.tau.prvKey, "betaTauG1" );
    curContribution.betaG1 = firstPoints[0];
    firstPoints = await processSection(6, "G2",  1, curContribution.key.beta.prvKey, curContribution.key.tau.prvKey, "betaTauG2" );
    curContribution.betaG2 = firstPoints[0];

    curContribution.partialHash = responseHasher.getPartialHash();

    const buffKey = new Uint8Array(curve.F1.n8*2*6+curve.F2.n8*2*3);

    toPtauPubKeyRpr(buffKey, 0, curve, curContribution.key, false);

    responseHasher.update(new Uint8Array(buffKey));
    const hashResponse = responseHasher.digest();

    if (logger) logger.info(formatHash(hashResponse, "Contribution Response Hash imported: "));

    const nextChallengeHasher = new Blake2b__default["default"](64);
    nextChallengeHasher.update(hashResponse);

    await hashSection(fdNew, "G1", 2, (2 ** power) * 2 -1, "tauG1");
    await hashSection(fdNew, "G2", 3, (2 ** power)       , "tauG2");
    await hashSection(fdNew, "G1", 4, (2 ** power)       , "alphaTauG1");
    await hashSection(fdNew, "G1", 5, (2 ** power)       , "betaTauG1");
    await hashSection(fdNew, "G2", 6, 1                  , "betaG2");

    curContribution.nextChallenge = nextChallengeHasher.digest();

    if (logger) logger.info(formatHash(curContribution.nextChallenge, "Next Challenge Hash: "));

    contributions.push(curContribution);

    await writeContributions(fdNew, curve, contributions);

    await fdOld.close();
    await fdNew.close();

    return hashResponse;

    async function processSection(sectionId, groupName, NPoints, first, inc, sectionName) {
        const res = [];
        fdOld.pos = sections[sectionId][0].p;

        await binFileUtils__namespace.startWriteSection(fdNew, sectionId);

        startSections[sectionId] = fdNew.pos;

        const G = curve[groupName];
        const sG = G.F.n8*2;
        const chunkSize = Math.floor((1<<20) / sG);   // 128Mb chunks
        let t = first;
        for (let i=0 ; i<NPoints ; i+= chunkSize) {
            if (logger) logger.debug(`processing: ${sectionName}: ${i}/${NPoints}`);
            const n= Math.min(NPoints-i, chunkSize );
            const buffIn = await fdOld.read(n * sG);
            const buffOutLEM = await G.batchApplyKey(buffIn, t, inc);

            /* Code to test the case where we don't have the 2^m-2 component
            if (sectionName== "tauG1") {
                const bz = new Uint8Array(64);
                buffOutLEM.set(bz, 64*((2 ** power) - 1 ));
            }
            */

            const promiseWrite = fdNew.write(buffOutLEM);
            const buffOutC = await G.batchLEMtoC(buffOutLEM);

            responseHasher.update(buffOutC);
            await promiseWrite;
            if (i==0)   // Return the 2 first points.
                for (let j=0; j<Math.min(2, NPoints); j++)
                    res.push(G.fromRprLEM(buffOutLEM, j*sG));
            t = curve.Fr.mul(t, curve.Fr.exp(inc, n));
        }

        await binFileUtils__namespace.endWriteSection(fdNew);

        return res;
    }


    async function hashSection(fdTo, groupName, sectionId, nPoints, sectionName) {

        const G = curve[groupName];
        const sG = G.F.n8*2;
        const nPointsChunk = Math.floor((1<<24)/sG);

        const oldPos = fdTo.pos;
        fdTo.pos = startSections[sectionId];

        for (let i=0; i< nPoints; i += nPointsChunk) {
            if ((logger)&&i) logger.debug(`Hashing ${sectionName}: ` + i);
            const n = Math.min(nPoints-i, nPointsChunk);

            const buffLEM = await fdTo.read(n * sG);

            const buffU = await G.batchLEMtoU(buffLEM);

            nextChallengeHasher.update(buffU);
        }

        fdTo.pos = oldPos;
    }


}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function preparePhase2(oldPtauFilename, newPTauFilename, logger) {

    const {fd: fdOld, sections} = await binFileUtils__namespace.readBinFile(oldPtauFilename, "ptau", 1);
    const {curve, power} = await readPTauHeader(fdOld, sections);

    const fdNew = await binFileUtils__namespace.createBinFile(newPTauFilename, "ptau", 1, 11);
    await writePTauHeader(fdNew, curve, power);

    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 2);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 3);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 4);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 5);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 6);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 7);

    await processSection(2, 12, "G1", "tauG1" );
    await processSection(3, 13, "G2", "tauG2" );
    await processSection(4, 14, "G1", "alphaTauG1" );
    await processSection(5, 15, "G1", "betaTauG1" );

    await fdOld.close();
    await fdNew.close();

    // await fs.promises.unlink(newPTauFilename+ ".tmp");

    return;

    async function processSection(oldSectionId, newSectionId, Gstr, sectionName) {
        if (logger) logger.debug("Starting section: "+sectionName);

        await binFileUtils__namespace.startWriteSection(fdNew, newSectionId);

        for (let p=0; p<=power; p++) {
            await processSectionPower(p);
        }

        if (oldSectionId == 2) {
            await processSectionPower(power+1);
        }

        await binFileUtils__namespace.endWriteSection(fdNew);


        async function processSectionPower(p) {
            const nPoints = 2 ** p;
            const G = curve[Gstr];
            curve.Fr;
            const sGin = G.F.n8*2;
            G.F.n8*3;

            let buff;
            buff = new ffjavascript.BigBuffer(nPoints*sGin);

            await binFileUtils__namespace.startReadUniqueSection(fdOld, sections, oldSectionId);
            if ((oldSectionId == 2)&&(p==power+1)) {
                await fdOld.readToBuffer(buff, 0,(nPoints-1)*sGin );
                buff.set(curve.G1.zeroAffine, (nPoints-1)*sGin );
            } else {
                await fdOld.readToBuffer(buff, 0,nPoints*sGin );
            }
            await binFileUtils__namespace.endReadSection(fdOld, true);


            buff = await G.lagrangeEvaluations(buff, "affine", "affine", logger, sectionName);
            await fdNew.write(buff);

/*
            if (p <= curve.Fr.s) {
                buff = await G.ifft(buff, "affine", "affine", logger, sectionName);
                await fdNew.write(buff);
            } else if (p == curve.Fr.s+1) {
                const smallM = 1<<curve.Fr.s;
                let t0 = new BigBuffer( smallM * sGmid );
                let t1 = new BigBuffer( smallM * sGmid );

                const shift_to_small_m = Fr.exp(Fr.shift, smallM);
                const one_over_denom = Fr.inv(Fr.sub(shift_to_small_m, Fr.one));

                let sInvAcc = Fr.one;
                for (let i=0; i<smallM; i++) {
                    const ti =  buff.slice(i*sGin, (i+1)*sGin);
                    const tmi = buff.slice((i+smallM)*sGin, (i+smallM+1)*sGin);

                    t0.set(
                        G.timesFr(
                            G.sub(
                                G.timesFr(ti , shift_to_small_m),
                                tmi
                            ),
                            one_over_denom
                        ),
                        i*sGmid
                    );
                    t1.set(
                        G.timesFr(
                            G.sub( tmi, ti),
                            Fr.mul(sInvAcc, one_over_denom)
                        ),
                        i*sGmid
                    );


                    sInvAcc = Fr.mul(sInvAcc, Fr.shiftInv);
                }
                t0 = await G.ifft(t0, "jacobian", "affine", logger, sectionName + " t0");
                await fdNew.write(t0);
                t0 = null;
                t1 = await G.ifft(t1, "jacobian", "affine", logger, sectionName + " t0");
                await fdNew.write(t1);

            } else {
                if (logger) logger.error("Power too big");
                throw new Error("Power to big");
            }
*/
        }
    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function truncate(ptauFilename, template, logger) {

    const {fd: fdOld, sections} = await binFileUtils__namespace.readBinFile(ptauFilename, "ptau", 1);
    const {curve, power, ceremonyPower} = await readPTauHeader(fdOld, sections);

    const sG1 = curve.G1.F.n8*2;
    const sG2 = curve.G2.F.n8*2;

    for (let p=1; p<power; p++) {
        await generateTruncate(p);
    }

    await fdOld.close();

    return true;

    async function generateTruncate(p) {

        let sP = p.toString();
        while (sP.length<2) sP = "0" + sP;

        if (logger) logger.debug("Writing Power: "+sP);

        const fdNew = await binFileUtils__namespace.createBinFile(template + sP + ".ptau", "ptau", 1, 11);
        await writePTauHeader(fdNew, curve, p, ceremonyPower);

        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 2, ((2 ** p)*2-1) * sG1 ); // tagG1
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 3, (2 ** p) * sG2); // tauG2
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 4, (2 ** p) * sG1); // alfaTauG1
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 5, (2 ** p) * sG1); // betaTauG1
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 6,  sG2); // betaTauG2
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 7); // contributions
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 12, ((2 ** (p+1))*2 -1) * sG1); // L_tauG1
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 13, ((2 ** p)*2 -1) * sG2); // L_tauG2
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 14, ((2 ** p)*2 -1) * sG1); // L_alfaTauG1
        await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 15, ((2 ** p)*2 -1) * sG1); // L_betaTauG1

        await fdNew.close();
    }


}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function convert(oldPtauFilename, newPTauFilename, logger) {

    const {fd: fdOld, sections} = await binFileUtils__namespace.readBinFile(oldPtauFilename, "ptau", 1);
    const {curve, power} = await readPTauHeader(fdOld, sections);

    const fdNew = await binFileUtils__namespace.createBinFile(newPTauFilename, "ptau", 1, 11);
    await writePTauHeader(fdNew, curve, power);

    // const fdTmp = await fastFile.createOverride(newPTauFilename+ ".tmp");

    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 2);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 3);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 4);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 5);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 6);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 7);

    await processSection(2, 12, "G1", "tauG1" );
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 13);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 14);
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 15);

    await fdOld.close();
    await fdNew.close();

    // await fs.promises.unlink(newPTauFilename+ ".tmp");

    return;

    async function processSection(oldSectionId, newSectionId, Gstr, sectionName) {
        if (logger) logger.debug("Starting section: "+sectionName);

        await binFileUtils__namespace.startWriteSection(fdNew, newSectionId);

        const size = sections[newSectionId][0].size;
        const chunkSize = fdOld.pageSize;
        await binFileUtils__namespace.startReadUniqueSection(fdOld, sections, newSectionId);
        for (let p=0; p<size; p+=chunkSize) {
            const l = Math.min(size -p, chunkSize);
            const buff = await fdOld.read(l);
            await fdNew.write(buff);
        }
        await binFileUtils__namespace.endReadSection(fdOld);

        if (oldSectionId == 2) {
            await processSectionPower(power+1);
        }

        await binFileUtils__namespace.endWriteSection(fdNew);

        async function processSectionPower(p) {
            const nPoints = 2 ** p;
            const G = curve[Gstr];
            const sGin = G.F.n8*2;

            let buff;
            buff = new ffjavascript.BigBuffer(nPoints*sGin);

            await binFileUtils__namespace.startReadUniqueSection(fdOld, sections, oldSectionId);
            if ((oldSectionId == 2)&&(p==power+1)) {
                await fdOld.readToBuffer(buff, 0,(nPoints-1)*sGin );
                buff.set(curve.G1.zeroAffine, (nPoints-1)*sGin );
            } else {
                await fdOld.readToBuffer(buff, 0,nPoints*sGin );
            }
            await binFileUtils__namespace.endReadSection(fdOld, true);

            buff = await G.lagrangeEvaluations(buff, "affine", "affine", logger, sectionName);
            await fdNew.write(buff);

/*
            if (p <= curve.Fr.s) {
                buff = await G.ifft(buff, "affine", "affine", logger, sectionName);
                await fdNew.write(buff);
            } else if (p == curve.Fr.s+1) {
                const smallM = 1<<curve.Fr.s;
                let t0 = new BigBuffer( smallM * sGmid );
                let t1 = new BigBuffer( smallM * sGmid );

                const shift_to_small_m = Fr.exp(Fr.shift, smallM);
                const one_over_denom = Fr.inv(Fr.sub(shift_to_small_m, Fr.one));

                let sInvAcc = Fr.one;
                for (let i=0; i<smallM; i++) {
                    if (i%10000) logger.debug(`sectionName prepare L calc: ${sectionName}, ${i}/${smallM}`);
                    const ti =  buff.slice(i*sGin, (i+1)*sGin);
                    const tmi = buff.slice((i+smallM)*sGin, (i+smallM+1)*sGin);

                    t0.set(
                        G.timesFr(
                            G.sub(
                                G.timesFr(ti , shift_to_small_m),
                                tmi
                            ),
                            one_over_denom
                        ),
                        i*sGmid
                    );
                    t1.set(
                        G.timesFr(
                            G.sub( tmi, ti),
                            Fr.mul(sInvAcc, one_over_denom)
                        ),
                        i*sGmid
                    );


                    sInvAcc = Fr.mul(sInvAcc, Fr.shiftInv);
                }
                t0 = await G.ifft(t0, "jacobian", "affine", logger, sectionName + " t0");
                await fdNew.write(t0);
                t0 = null;
                t1 = await G.ifft(t1, "jacobian", "affine", logger, sectionName + " t1");
                await fdNew.write(t1);

            } else {
                if (logger) logger.error("Power too big");
                throw new Error("Power to big");
            }
*/
        }


    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function exportJson(pTauFilename, verbose) {
    const {fd, sections} = await binFileUtils__namespace.readBinFile(pTauFilename, "ptau", 1);

    const {curve, power} = await readPTauHeader(fd, sections);

    const pTau = {};
    pTau.q = curve.q;
    pTau.power = power;
    pTau.contributions = await readContributions(fd, curve, sections);

    pTau.tauG1 = await exportSection(2, "G1", (2 ** power)*2 -1, "tauG1");
    pTau.tauG2 = await exportSection(3, "G2", (2 ** power), "tauG2");
    pTau.alphaTauG1 = await exportSection(4, "G1", (2 ** power), "alphaTauG1");
    pTau.betaTauG1 = await exportSection(5, "G1", (2 ** power), "betaTauG1");
    pTau.betaG2 = await exportSection(6, "G2", 1, "betaG2");

    pTau.lTauG1 = await exportLagrange(12, "G1", "lTauG1");
    pTau.lTauG2 = await exportLagrange(13, "G2", "lTauG2");
    pTau.lAlphaTauG1 = await exportLagrange(14, "G1", "lAlphaTauG2");
    pTau.lBetaTauG1 = await exportLagrange(15, "G1", "lBetaTauG2");

    await fd.close();

    return stringifyBigIntsWithField(curve.Fr, pTau);



    async function exportSection(sectionId, groupName, nPoints, sectionName) {
        const G = curve[groupName];
        const sG = G.F.n8*2;

        const res = [];
        await binFileUtils__namespace.startReadUniqueSection(fd, sections, sectionId);
        for (let i=0; i< nPoints; i++) {
            if ((verbose)&&i&&(i%10000 == 0)) console.log(`${sectionName}: ` + i);
            const buff = await fd.read(sG);
            res.push(G.fromRprLEM(buff, 0));
        }
        await binFileUtils__namespace.endReadSection(fd);

        return res;
    }

    async function exportLagrange(sectionId, groupName, sectionName) {
        const G = curve[groupName];
        const sG = G.F.n8*2;

        const res = [];
        await binFileUtils__namespace.startReadUniqueSection(fd, sections, sectionId);
        for (let p=0; p<=power; p++) {
            if (verbose) console.log(`${sectionName}: Power: ${p}`);
            res[p] = [];
            const nPoints = (2 ** p);
            for (let i=0; i<nPoints; i++) {
                if ((verbose)&&i&&(i%10000 == 0)) console.log(`${sectionName}: ${i}/${nPoints}`);
                const buff = await fd.read(sG);
                res[p].push(G.fromRprLEM(buff, 0));
            }
        }
        await binFileUtils__namespace.endReadSection(fd, true);
        return res;
    }


}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

var powersoftau = /*#__PURE__*/Object.freeze({
    __proto__: null,
    newAccumulator: newAccumulator,
    exportChallenge: exportChallenge,
    importResponse: importResponse,
    verify: verify,
    challengeContribute: challengeContribute,
    beacon: beacon$1,
    contribute: contribute,
    preparePhase2: preparePhase2,
    truncate: truncate,
    convert: convert,
    exportJson: exportJson
});

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

function r1csPrint(r1cs, syms, logger) {
    for (let i=0; i<r1cs.constraints.length; i++) {
        printCostraint(r1cs.constraints[i]);
    }
    function printCostraint(c) {
        const lc2str = (lc) => {
            let S = "";
            const keys = Object.keys(lc);
            keys.forEach( (k) => {
                let name = syms.varIdx2Name[k];
                if (name == "one") name = "";

                let vs = r1cs.curve.Fr.toString(lc[k]);
                if (vs == "1") vs = "";  // Do not show ones
                if (vs == "-1") vs = "-";  // Do not show ones
                if ((S!="")&&(vs[0]!="-")) vs = "+"+vs;
                if (S!="") vs = " "+vs;
                S= S + vs   + name;
            });
            return S;
        };
        const S = `[ ${lc2str(c[0])} ] * [ ${lc2str(c[1])} ] - [ ${lc2str(c[2])} ] = 0`;
        if (logger) logger.info(S);
    }

}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

const bls12381r = ffjavascript.Scalar.e("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
const bn128r = ffjavascript.Scalar.e("21888242871839275222246405745257275088548364400416034343698204186575808495617");

async function r1csInfo(r1csName, logger) {

    const cir = await r1csfile.readR1cs(r1csName);

    if (ffjavascript.Scalar.eq(cir.prime, bn128r)) {
        if (logger) logger.info("Curve: bn-128");
    } else if (ffjavascript.Scalar.eq(cir.prime, bls12381r)) {
        if (logger) logger.info("Curve: bls12-381");
    } else {
        if (logger) logger.info(`Unknown Curve. Prime: ${ffjavascript.Scalar.toString(cir.prime)}`);
    }
    if (logger) logger.info(`# of Wires: ${cir.nVars}`);
    if (logger) logger.info(`# of Constraints: ${cir.nConstraints}`);
    if (logger) logger.info(`# of Private Inputs: ${cir.nPrvInputs}`);
    if (logger) logger.info(`# of Public Inputs: ${cir.nPubInputs}`);
    if (logger) logger.info(`# of Labels: ${cir.nLabels}`);
    if (logger) logger.info(`# of Outputs: ${cir.nOutputs}`);

    return cir;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/


async function r1csExportJson(r1csFileName, logger) {

    const cir = await r1csfile.readR1cs(r1csFileName, true, true, true, logger);
    const Fr=cir.curve.Fr;
    delete cir.curve;
    delete cir.F;

    return stringifyBigIntsWithField(Fr, cir);
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

var r1cs = /*#__PURE__*/Object.freeze({
    __proto__: null,
    print: r1csPrint,
    info: r1csInfo,
    exportJson: r1csExportJson
});

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function loadSymbols(symFileName) {
    const sym = {
        labelIdx2Name: [ "one" ],
        varIdx2Name: [ "one" ],
        componentIdx2Name: []
    };
    const fd = await fastFile__namespace.readExisting(symFileName);
    const buff = await fd.read(fd.totalSize);
    const symsStr = new TextDecoder("utf-8").decode(buff);
    const lines = symsStr.split("\n");
    for (let i=0; i<lines.length; i++) {
        const arr = lines[i].split(",");
        if (arr.length!=4) continue;
        if (sym.varIdx2Name[arr[1]]) {
            sym.varIdx2Name[arr[1]] += "|" + arr[3];
        } else {
            sym.varIdx2Name[arr[1]] = arr[3];
        }
        sym.labelIdx2Name[arr[0]] = arr[3];
        if (!sym.componentIdx2Name[arr[2]]) {
            sym.componentIdx2Name[arr[2]] = extractComponent(arr[3]);
        }
    }

    await fd.close();

    return sym;

    function extractComponent(name) {
        const arr = name.split(".");
        arr.pop(); // Remove the lasr element
        return arr.join(".");
    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const {unstringifyBigInts: unstringifyBigInts$3} = ffjavascript.utils;


async function wtnsDebug(_input, wasmFileName, wtnsFileName, symName, options, logger) {

    const input = unstringifyBigInts$3(_input);

    const fdWasm = await fastFile__namespace.readExisting(wasmFileName);
    const wasm = await fdWasm.read(fdWasm.totalSize);
    await fdWasm.close();


    let wcOps = {
        sanityCheck: true
    };
    let sym = await loadSymbols(symName);
    if (options.set) {
        if (!sym) sym = await loadSymbols(symName);
        wcOps.logSetSignal= function(labelIdx, value) {
            // The line below splits the arrow log into 2 strings to avoid some Secure ECMAScript issues
            if (logger) logger.info("SET " + sym.labelIdx2Name[labelIdx] + " <" + "-- " + value.toString());
        };
    }
    if (options.get) {
        if (!sym) sym = await loadSymbols(symName);
        wcOps.logGetSignal= function(varIdx, value) {
            // The line below splits the arrow log into 2 strings to avoid some Secure ECMAScript issues
            if (logger) logger.info("GET " + sym.labelIdx2Name[varIdx] + " --" + "> " + value.toString());
        };
    }
    if (options.trigger) {
        if (!sym) sym = await loadSymbols(symName);
        wcOps.logStartComponent= function(cIdx) {
            if (logger) logger.info("START: " + sym.componentIdx2Name[cIdx]);
        };
        wcOps.logFinishComponent= function(cIdx) {
            if (logger) logger.info("FINISH: " + sym.componentIdx2Name[cIdx]);
        };
    }
    wcOps.sym = sym;

    const wc = await circom_runtime.WitnessCalculatorBuilder(wasm, wcOps);
    const w = await wc.calculateWitness(input);

    const fdWtns = await binFileUtils__namespace.createBinFile(wtnsFileName, "wtns", 2, 2);

    await write(fdWtns, w, wc.prime);

    await fdWtns.close();
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function wtnsExportJson(wtnsFileName) {

    const w = await read(wtnsFileName);

    return w;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

var wtns = /*#__PURE__*/Object.freeze({
    __proto__: null,
    calculate: wtnsCalculate,
    debug: wtnsDebug,
    exportJson: wtnsExportJson
});

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

const SUBARRAY_SIZE = 0x40000;

const BigArrayHandler = {
    get: function(obj, prop) {
        if (!isNaN(prop)) {
            return obj.getElement(prop);
        } else return obj[prop];
    },
    set: function(obj, prop, value) {
        if (!isNaN(prop)) {
            return obj.setElement(prop, value);
        } else {
            obj[prop] = value;
            return true;
        }
    }
};

class _BigArray {
    constructor (initSize) {
        this.length = initSize || 0;
        this.arr = new Array(SUBARRAY_SIZE);

        for (let i=0; i<initSize; i+=SUBARRAY_SIZE) {
            this.arr[i/SUBARRAY_SIZE] = new Array(Math.min(SUBARRAY_SIZE, initSize - i));
        }
        return this;
    }
    push () {
        for (let i=0; i<arguments.length; i++) {
            this.setElement (this.length, arguments[i]);
        }
    }

    slice (f, t) {
        const arr = new Array(t-f);
        for (let i=f; i< t; i++) arr[i-f] = this.getElement(i);
        return arr;
    }
    getElement(idx) {
        idx = parseInt(idx);
        const idx1 = Math.floor(idx / SUBARRAY_SIZE);
        const idx2 = idx % SUBARRAY_SIZE;
        return this.arr[idx1] ? this.arr[idx1][idx2] : undefined;
    }
    setElement(idx, value) {
        idx = parseInt(idx);
        const idx1 = Math.floor(idx / SUBARRAY_SIZE);
        if (!this.arr[idx1]) {
            this.arr[idx1] = new Array(SUBARRAY_SIZE);
        }
        const idx2 = idx % SUBARRAY_SIZE;
        this.arr[idx1][idx2] = value;
        if (idx >= this.length) this.length = idx+1;
        return true;
    }
    getKeys() {
        const newA = new BigArray();
        for (let i=0; i<this.arr.length; i++) {
            if (this.arr[i]) {
                for (let j=0; j<this.arr[i].length; j++) {
                    if (typeof this.arr[i][j] !== "undefined") {
                        newA.push(i*SUBARRAY_SIZE+j);
                    }
                }
            }
        }
        return newA;
    }
}

class BigArray {
    constructor( initSize ) {
        const obj = new _BigArray(initSize);
        const extObj = new Proxy(obj, BigArrayHandler);
        return extObj;
    }
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/


async function newZKey(r1csName, ptauName, zkeyName, logger) {

    const TAU_G1 = 0;
    const TAU_G2 = 1;
    const ALPHATAU_G1 = 2;
    const BETATAU_G1 = 3;
    await Blake2b__default["default"].ready();
    const csHasher = Blake2b__default["default"](64);

    const {fd: fdPTau, sections: sectionsPTau} = await binFileUtils.readBinFile(ptauName, "ptau", 1, 1<<22, 1<<24);
    const {curve, power} = await readPTauHeader(fdPTau, sectionsPTau);
    const {fd: fdR1cs, sections: sectionsR1cs} = await binFileUtils.readBinFile(r1csName, "r1cs", 1, 1<<22, 1<<24);
    const r1cs = await r1csfile.readR1csHeader(fdR1cs, sectionsR1cs, false);

    const fdZKey = await binFileUtils.createBinFile(zkeyName, "zkey", 1, 10, 1<<22, 1<<24);

    const sG1 = curve.G1.F.n8*2;
    const sG2 = curve.G2.F.n8*2;

    if (r1cs.prime != curve.r) {
        if (logger) logger.error("r1cs curve does not match powers of tau ceremony curve");
        return -1;
    }

    const cirPower = log2(r1cs.nConstraints + r1cs.nPubInputs + r1cs.nOutputs +1 -1) +1;

    if (cirPower > power) {
        if (logger) logger.error(`circuit too big for this power of tau ceremony. ${r1cs.nConstraints}*2 > 2**${power}`);
        return -1;
    }

    if (!sectionsPTau[12]) {
        if (logger) logger.error("Powers of tau is not prepared.");
        return -1;
    }

    const nPublic = r1cs.nOutputs + r1cs.nPubInputs;
    const domainSize = 2 ** cirPower;

    // Write the header
    ///////////
    await binFileUtils.startWriteSection(fdZKey, 1);
    await fdZKey.writeULE32(1); // Groth
    await binFileUtils.endWriteSection(fdZKey);

    // Write the Groth header section
    ///////////

    await binFileUtils.startWriteSection(fdZKey, 2);
    const primeQ = curve.q;
    const n8q = (Math.floor( (ffjavascript.Scalar.bitLength(primeQ) - 1) / 64) +1)*8;

    const primeR = curve.r;
    const n8r = (Math.floor( (ffjavascript.Scalar.bitLength(primeR) - 1) / 64) +1)*8;
    const Rr = ffjavascript.Scalar.mod(ffjavascript.Scalar.shl(1, n8r*8), primeR);
    const R2r = curve.Fr.e(ffjavascript.Scalar.mod(ffjavascript.Scalar.mul(Rr,Rr), primeR));

    await fdZKey.writeULE32(n8q);
    await binFileUtils.writeBigInt(fdZKey, primeQ, n8q);
    await fdZKey.writeULE32(n8r);
    await binFileUtils.writeBigInt(fdZKey, primeR, n8r);
    await fdZKey.writeULE32(r1cs.nVars);                         // Total number of bars
    await fdZKey.writeULE32(nPublic);                       // Total number of public vars (not including ONE)
    await fdZKey.writeULE32(domainSize);                  // domainSize

    let bAlpha1;
    bAlpha1 = await fdPTau.read(sG1, sectionsPTau[4][0].p);
    await fdZKey.write(bAlpha1);
    bAlpha1 = await curve.G1.batchLEMtoU(bAlpha1);
    csHasher.update(bAlpha1);

    let bBeta1;
    bBeta1 = await fdPTau.read(sG1, sectionsPTau[5][0].p);
    await fdZKey.write(bBeta1);
    bBeta1 = await curve.G1.batchLEMtoU(bBeta1);
    csHasher.update(bBeta1);

    let bBeta2;
    bBeta2 = await fdPTau.read(sG2, sectionsPTau[6][0].p);
    await fdZKey.write(bBeta2);
    bBeta2 = await curve.G2.batchLEMtoU(bBeta2);
    csHasher.update(bBeta2);

    const bg1 = new Uint8Array(sG1);
    curve.G1.toRprLEM(bg1, 0, curve.G1.g);
    const bg2 = new Uint8Array(sG2);
    curve.G2.toRprLEM(bg2, 0, curve.G2.g);
    const bg1U = new Uint8Array(sG1);
    curve.G1.toRprUncompressed(bg1U, 0, curve.G1.g);
    const bg2U = new Uint8Array(sG2);
    curve.G2.toRprUncompressed(bg2U, 0, curve.G2.g);

    await fdZKey.write(bg2);        // gamma2
    await fdZKey.write(bg1);        // delta1
    await fdZKey.write(bg2);        // delta2
    csHasher.update(bg2U);      // gamma2
    csHasher.update(bg1U);      // delta1
    csHasher.update(bg2U);      // delta2
    await binFileUtils.endWriteSection(fdZKey);

    if (logger) logger.info("Reading r1cs");
    let sR1cs = await binFileUtils.readSection(fdR1cs, sectionsR1cs, 2);

    const A = new BigArray(r1cs.nVars);
    const B1 = new BigArray(r1cs.nVars);
    const B2 = new BigArray(r1cs.nVars);
    const C = new BigArray(r1cs.nVars- nPublic -1);
    const IC = new Array(nPublic+1);

    if (logger) logger.info("Reading tauG1");
    let sTauG1 = await binFileUtils.readSection(fdPTau, sectionsPTau, 12, (domainSize -1)*sG1, domainSize*sG1);
    if (logger) logger.info("Reading tauG2");
    let sTauG2 = await binFileUtils.readSection(fdPTau, sectionsPTau, 13, (domainSize -1)*sG2, domainSize*sG2);
    if (logger) logger.info("Reading alphatauG1");
    let sAlphaTauG1 = await binFileUtils.readSection(fdPTau, sectionsPTau, 14, (domainSize -1)*sG1, domainSize*sG1);
    if (logger) logger.info("Reading betatauG1");
    let sBetaTauG1 = await binFileUtils.readSection(fdPTau, sectionsPTau, 15, (domainSize -1)*sG1, domainSize*sG1);

    await processConstraints();

    await composeAndWritePoints(3, "G1", IC, "IC");

    await writeHs();

    await hashHPoints();

    await composeAndWritePoints(8, "G1", C, "C");
    await composeAndWritePoints(5, "G1", A, "A");
    await composeAndWritePoints(6, "G1", B1, "B1");
    await composeAndWritePoints(7, "G2", B2, "B2");

    const csHash = csHasher.digest();
    // Contributions section
    await binFileUtils.startWriteSection(fdZKey, 10);
    await fdZKey.write(csHash);
    await fdZKey.writeULE32(0);
    await binFileUtils.endWriteSection(fdZKey);

    if (logger) logger.info(formatHash(csHash, "Circuit hash: "));


    await fdZKey.close();
    await fdR1cs.close();
    await fdPTau.close();

    return csHash;

    async function writeHs() {
        await binFileUtils.startWriteSection(fdZKey, 9);
        const buffOut = new ffjavascript.BigBuffer(domainSize*sG1);
        if (cirPower < curve.Fr.s) {
            let sTauG1 = await binFileUtils.readSection(fdPTau, sectionsPTau, 12, (domainSize*2-1)*sG1, domainSize*2*sG1);
            for (let i=0; i< domainSize; i++) {
                if ((logger)&&(i%10000 == 0)) logger.debug(`spliting buffer: ${i}/${domainSize}`);
                const buff = sTauG1.slice( (i*2+1)*sG1, (i*2+1)*sG1 + sG1 );
                buffOut.set(buff, i*sG1);
            }
        } else if (cirPower == curve.Fr.s) {
            const o = sectionsPTau[12][0].p + ((2 ** (cirPower+1)) -1)*sG1;
            await fdPTau.readToBuffer(buffOut, 0, domainSize*sG1, o + domainSize*sG1);
        } else {
            if (logger) logger.error("Circuit too big");
            throw new Error("Circuit too big for this curve");
        }
        await fdZKey.write(buffOut);
        await binFileUtils.endWriteSection(fdZKey);
    }

    async function processConstraints() {
        const buffCoeff = new Uint8Array(12 + curve.Fr.n8);
        const buffCoeffV = new DataView(buffCoeff.buffer);
        const bOne = new Uint8Array(curve.Fr.n8);
        curve.Fr.toRprLE(bOne, 0, curve.Fr.e(1));

        let r1csPos = 0;

        function r1cs_readULE32() {
            const buff = sR1cs.slice(r1csPos, r1csPos+4);
            r1csPos += 4;
            const buffV = new DataView(buff.buffer);
            return buffV.getUint32(0, true);
        }

        const coefs = new BigArray();
        for (let c=0; c<r1cs.nConstraints; c++) {
            if ((logger)&&(c%10000 == 0)) logger.debug(`processing constraints: ${c}/${r1cs.nConstraints}`);
            const nA = r1cs_readULE32();
            for (let i=0; i<nA; i++) {
                const s = r1cs_readULE32();
                const coefp = r1csPos;
                r1csPos += curve.Fr.n8;

                const l1t = TAU_G1;
                const l1 = sG1*c;
                const l2t = BETATAU_G1;
                const l2 = sG1*c;
                if (typeof A[s] === "undefined") A[s] = [];
                A[s].push([l1t, l1, coefp]);

                if (s <= nPublic) {
                    if (typeof IC[s] === "undefined") IC[s] = [];
                    IC[s].push([l2t, l2, coefp]);
                } else {
                    if (typeof C[s- nPublic -1] === "undefined") C[s- nPublic -1] = [];
                    C[s - nPublic -1].push([l2t, l2, coefp]);
                }
                coefs.push([0, c, s, coefp]);
            }

            const nB = r1cs_readULE32();
            for (let i=0; i<nB; i++) {
                const s = r1cs_readULE32();
                const coefp = r1csPos;
                r1csPos += curve.Fr.n8;

                const l1t = TAU_G1;
                const l1 = sG1*c;
                const l2t = TAU_G2;
                const l2 = sG2*c;
                const l3t = ALPHATAU_G1;
                const l3 = sG1*c;
                if (typeof B1[s] === "undefined") B1[s] = [];
                B1[s].push([l1t, l1, coefp]);
                if (typeof B2[s] === "undefined") B2[s] = [];
                B2[s].push([l2t, l2, coefp]);

                if (s <= nPublic) {
                    if (typeof IC[s] === "undefined") IC[s] = [];
                    IC[s].push([l3t, l3, coefp]);
                } else {
                    if (typeof C[s- nPublic -1] === "undefined") C[s- nPublic -1] = [];
                    C[s- nPublic -1].push([l3t, l3, coefp]);
                }

                coefs.push([1, c, s, coefp]);
            }

            const nC = r1cs_readULE32();
            for (let i=0; i<nC; i++) {
                const s = r1cs_readULE32();
                const coefp = r1csPos;
                r1csPos += curve.Fr.n8;

                const l1t = TAU_G1;
                const l1 = sG1*c;
                if (s <= nPublic) {
                    if (typeof IC[s] === "undefined") IC[s] = [];
                    IC[s].push([l1t, l1, coefp]);
                } else {
                    if (typeof C[s- nPublic -1] === "undefined") C[s- nPublic -1] = [];
                    C[s- nPublic -1].push([l1t, l1, coefp]);
                }
            }
        }

        for (let s = 0; s <= nPublic ; s++) {
            const l1t = TAU_G1;
            const l1 = sG1*(r1cs.nConstraints + s);
            const l2t = BETATAU_G1;
            const l2 = sG1*(r1cs.nConstraints + s);
            if (typeof A[s] === "undefined") A[s] = [];
            A[s].push([l1t, l1, -1]);
            if (typeof IC[s] === "undefined") IC[s] = [];
            IC[s].push([l2t, l2, -1]);
            coefs.push([0, r1cs.nConstraints + s, s, -1]);
        }


        await binFileUtils.startWriteSection(fdZKey, 4);

        const buffSection = new ffjavascript.BigBuffer(coefs.length*(12+curve.Fr.n8) + 4);

        const buff4 = new Uint8Array(4);
        const buff4V = new DataView(buff4.buffer);
        buff4V.setUint32(0, coefs.length, true);
        buffSection.set(buff4);
        let coefsPos = 4;
        for (let i=0; i<coefs.length; i++) {
            if ((logger)&&(i%100000 == 0)) logger.debug(`writing coeffs: ${i}/${coefs.length}`);
            writeCoef(coefs[i]);
        }

        await fdZKey.write(buffSection);
        await binFileUtils.endWriteSection(fdZKey);

        function writeCoef(c) {
            buffCoeffV.setUint32(0, c[0], true);
            buffCoeffV.setUint32(4, c[1], true);
            buffCoeffV.setUint32(8, c[2], true);
            let n;
            if (c[3]>=0) {
                n = curve.Fr.fromRprLE(sR1cs.slice(c[3], c[3] + curve.Fr.n8), 0);
            } else {
                n = curve.Fr.fromRprLE(bOne, 0);
            }
            const nR2 = curve.Fr.mul(n, R2r);
            curve.Fr.toRprLE(buffCoeff, 12, nR2);
            buffSection.set(buffCoeff, coefsPos);
            coefsPos += buffCoeff.length;
        }

    }

    async function composeAndWritePoints(idSection, groupName, arr, sectionName) {
        const CHUNK_SIZE= 1<<15;
        const G = curve[groupName];

        hashU32(arr.length);
        await binFileUtils.startWriteSection(fdZKey, idSection);

        let opPromises = [];

        let i=0;
        while (i<arr.length) {

            let t=0;
            while ((i<arr.length)&&(t<curve.tm.concurrency)) {
                if (logger)  logger.debug(`Writing points start ${sectionName}: ${i}/${arr.length}`);
                let n = 1;
                let nP = (arr[i] ? arr[i].length : 0);
                while ((i + n < arr.length) && (nP + (arr[i+n] ? arr[i+n].length : 0) < CHUNK_SIZE) && (n<CHUNK_SIZE)) {
                    nP += (arr[i+n] ? arr[i+n].length : 0);
                    n ++;
                }
                const subArr = arr.slice(i, i + n);
                const _i = i;
                opPromises.push(composeAndWritePointsThread(groupName, subArr, logger, sectionName).then( (r) => {
                    if (logger)  logger.debug(`Writing points end ${sectionName}: ${_i}/${arr.length}`);
                    return r;
                }));
                i += n;
                t++;
            }

            const result = await Promise.all(opPromises);

            for (let k=0; k<result.length; k++) {
                await fdZKey.write(result[k][0]);
                const buff = await G.batchLEMtoU(result[k][0]);
                csHasher.update(buff);
            }
            opPromises = [];

        }
        await binFileUtils.endWriteSection(fdZKey);

    }

    async function composeAndWritePointsThread(groupName, arr, logger, sectionName) {
        const G = curve[groupName];
        const sGin = G.F.n8*2;
        const sGmid = G.F.n8*3;
        const sGout = G.F.n8*2;
        let fnExp, fnMultiExp, fnBatchToAffine, fnZero;
        if (groupName == "G1") {
            fnExp = "g1m_timesScalarAffine";
            fnMultiExp = "g1m_multiexpAffine";
            fnBatchToAffine = "g1m_batchToAffine";
            fnZero = "g1m_zero";
        } else if (groupName == "G2") {
            fnExp = "g2m_timesScalarAffine";
            fnMultiExp = "g2m_multiexpAffine";
            fnBatchToAffine = "g2m_batchToAffine";
            fnZero = "g2m_zero";
        } else {
            throw new Error("Invalid group");
        }
        let acc =0;
        for (let i=0; i<arr.length; i++) acc += arr[i] ? arr[i].length : 0;
        let bBases, bScalars;
        if (acc> 2<<14) {
            bBases = new ffjavascript.BigBuffer(acc*sGin);
            bScalars = new ffjavascript.BigBuffer(acc*curve.Fr.n8);
        } else {
            bBases = new Uint8Array(acc*sGin);
            bScalars = new Uint8Array(acc*curve.Fr.n8);
        }
        let pB =0;
        let pS =0;

        const sBuffs = [
            sTauG1,
            sTauG2,
            sAlphaTauG1,
            sBetaTauG1
        ];

        const bOne = new Uint8Array(curve.Fr.n8);
        curve.Fr.toRprLE(bOne, 0, curve.Fr.e(1));

        let offset = 0;
        for (let i=0; i<arr.length; i++) {
            if (!arr[i]) continue;
            for (let j=0; j<arr[i].length; j++) {
                if ((logger)&&(j)&&(j%10000 == 0))  logger.debug(`Configuring big array ${sectionName}: ${j}/${arr[i].length}`);
                bBases.set(
                    sBuffs[arr[i][j][0]].slice(
                        arr[i][j][1],
                        arr[i][j][1] + sGin
                    ), offset*sGin
                );
                if (arr[i][j][2]>=0) {
                    bScalars.set(
                        sR1cs.slice(
                            arr[i][j][2],
                            arr[i][j][2] + curve.Fr.n8
                        ),
                        offset*curve.Fr.n8
                    );
                } else {
                    bScalars.set(bOne, offset*curve.Fr.n8);
                }
                offset ++;
            }
        }

        if (arr.length>1) {
            const task = [];
            task.push({cmd: "ALLOCSET", var: 0, buff: bBases});
            task.push({cmd: "ALLOCSET", var: 1, buff: bScalars});
            task.push({cmd: "ALLOC", var: 2, len: arr.length*sGmid});
            pB = 0;
            pS = 0;
            let pD =0;
            for (let i=0; i<arr.length; i++) {
                if (!arr[i]) {
                    task.push({cmd: "CALL", fnName: fnZero, params: [
                        {var: 2, offset: pD}
                    ]});
                    pD += sGmid;
                    continue;
                }
                if (arr[i].length == 1) {
                    task.push({cmd: "CALL", fnName: fnExp, params: [
                        {var: 0, offset: pB},
                        {var: 1, offset: pS},
                        {val: curve.Fr.n8},
                        {var: 2, offset: pD}
                    ]});
                } else {
                    task.push({cmd: "CALL", fnName: fnMultiExp, params: [
                        {var: 0, offset: pB},
                        {var: 1, offset: pS},
                        {val: curve.Fr.n8},
                        {val: arr[i].length},
                        {var: 2, offset: pD}
                    ]});
                }
                pB += sGin*arr[i].length;
                pS += curve.Fr.n8*arr[i].length;
                pD += sGmid;
            }
            task.push({cmd: "CALL", fnName: fnBatchToAffine, params: [
                {var: 2},
                {val: arr.length},
                {var: 2},
            ]});
            task.push({cmd: "GET", out: 0, var: 2, len: arr.length*sGout});

            const res = await curve.tm.queueAction(task);
            return res;
        } else {
            let res = await G.multiExpAffine(bBases, bScalars, logger, sectionName);
            res = [ G.toAffine(res) ];
            return res;
        }
    }


    async function hashHPoints() {
        const CHUNK_SIZE = 1<<14;

        hashU32(domainSize-1);

        for (let i=0; i<domainSize-1; i+= CHUNK_SIZE) {
            if (logger)  logger.debug(`HashingHPoints: ${i}/${domainSize}`);
            const n = Math.min(domainSize-1, CHUNK_SIZE);
            await hashHPointsChunk(i, n);
        }
    }

    async function hashHPointsChunk(offset, nPoints) {
        const buff1 = await fdPTau.read(nPoints *sG1, sectionsPTau[2][0].p + (offset + domainSize)*sG1);
        const buff2 = await fdPTau.read(nPoints *sG1, sectionsPTau[2][0].p + offset*sG1);
        const concurrency= curve.tm.concurrency;
        const nPointsPerThread = Math.floor(nPoints / concurrency);
        const opPromises = [];
        for (let i=0; i<concurrency; i++) {
            let n;
            if (i< concurrency-1) {
                n = nPointsPerThread;
            } else {
                n = nPoints - i*nPointsPerThread;
            }
            if (n==0) continue;

            const subBuff1 = buff1.slice(i*nPointsPerThread*sG1, (i*nPointsPerThread+n)*sG1);
            const subBuff2 = buff2.slice(i*nPointsPerThread*sG1, (i*nPointsPerThread+n)*sG1);
            opPromises.push(hashHPointsThread(subBuff1, subBuff2));
        }


        const result = await Promise.all(opPromises);

        for (let i=0; i<result.length; i++) {
            csHasher.update(result[i][0]);
        }
    }

    async function hashHPointsThread(buff1, buff2) {
        const nPoints = buff1.byteLength/sG1;
        const sGmid = curve.G1.F.n8*3;
        const task = [];
        task.push({cmd: "ALLOCSET", var: 0, buff: buff1});
        task.push({cmd: "ALLOCSET", var: 1, buff: buff2});
        task.push({cmd: "ALLOC", var: 2, len: nPoints*sGmid});
        for (let i=0; i<nPoints; i++) {
            task.push({
                cmd: "CALL",
                fnName: "g1m_subAffine",
                params: [
                    {var: 0, offset: i*sG1},
                    {var: 1, offset: i*sG1},
                    {var: 2, offset: i*sGmid},
                ]
            });
        }
        task.push({cmd: "CALL", fnName: "g1m_batchToAffine", params: [
            {var: 2},
            {val: nPoints},
            {var: 2},
        ]});
        task.push({cmd: "CALL", fnName: "g1m_batchLEMtoU", params: [
            {var: 2},
            {val: nPoints},
            {var: 2},
        ]});
        task.push({cmd: "GET", out: 0, var: 2, len: nPoints*sG1});

        const res = await curve.tm.queueAction(task);

        return res;
    }

    function hashU32(n) {
        const buff = new Uint8Array(4);
        const buffV = new DataView(buff.buffer, buff.byteOffset, buff.byteLength);
        buffV.setUint32(0, n, false);
        csHasher.update(buff);
    }

}

async function phase2exportMPCParams(zkeyName, mpcparamsName, logger) {

    const {fd: fdZKey, sections: sectionsZKey} = await binFileUtils__namespace.readBinFile(zkeyName, "zkey", 2);
    const zkey = await readHeader$1(fdZKey, sectionsZKey);
    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurveFromQ(zkey.q);
    const sG1 = curve.G1.F.n8*2;
    const sG2 = curve.G2.F.n8*2;

    const mpcParams = await readMPCParams(fdZKey, curve, sectionsZKey);

    const fdMPCParams = await fastFile__namespace.createOverride(mpcparamsName);

    /////////////////////
    // Verification Key Section
    /////////////////////
    await writeG1(zkey.vk_alpha_1);
    await writeG1(zkey.vk_beta_1);
    await writeG2(zkey.vk_beta_2);
    await writeG2(zkey.vk_gamma_2);
    await writeG1(zkey.vk_delta_1);
    await writeG2(zkey.vk_delta_2);

    // IC
    let buffBasesIC;
    buffBasesIC = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 3);
    buffBasesIC = await curve.G1.batchLEMtoU(buffBasesIC);

    await writePointArray("G1", buffBasesIC);

    /////////////////////
    // h Section
    /////////////////////
    const buffBasesH_Lodd = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 9);

    let buffBasesH_Tau;
    buffBasesH_Tau = await curve.G1.fft(buffBasesH_Lodd, "affine", "jacobian", logger);
    buffBasesH_Tau = await curve.G1.batchApplyKey(buffBasesH_Tau, curve.Fr.neg(curve.Fr.e(2)), curve.Fr.w[zkey.power+1], "jacobian", "affine", logger);

    // Remove last element.  (The degree of H will be allways m-2)
    buffBasesH_Tau = buffBasesH_Tau.slice(0, buffBasesH_Tau.byteLength - sG1);
    buffBasesH_Tau = await curve.G1.batchLEMtoU(buffBasesH_Tau);
    await writePointArray("G1", buffBasesH_Tau);

    /////////////////////
    // L section
    /////////////////////
    let buffBasesC;
    buffBasesC = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 8);
    buffBasesC = await curve.G1.batchLEMtoU(buffBasesC);
    await writePointArray("G1", buffBasesC);

    /////////////////////
    // A Section (C section)
    /////////////////////
    let buffBasesA;
    buffBasesA = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 5);
    buffBasesA = await curve.G1.batchLEMtoU(buffBasesA);
    await writePointArray("G1", buffBasesA);

    /////////////////////
    // B1 Section
    /////////////////////
    let buffBasesB1;
    buffBasesB1 = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 6);
    buffBasesB1 = await curve.G1.batchLEMtoU(buffBasesB1);
    await writePointArray("G1", buffBasesB1);

    /////////////////////
    // B2 Section
    /////////////////////
    let buffBasesB2;
    buffBasesB2 = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 7);
    buffBasesB2 = await curve.G2.batchLEMtoU(buffBasesB2);
    await writePointArray("G2", buffBasesB2);

    await fdMPCParams.write(mpcParams.csHash);
    await writeU32(mpcParams.contributions.length);

    for (let i=0; i<mpcParams.contributions.length; i++) {
        const c = mpcParams.contributions[i];
        await writeG1(c.deltaAfter);
        await writeG1(c.delta.g1_s);
        await writeG1(c.delta.g1_sx);
        await writeG2(c.delta.g2_spx);
        await fdMPCParams.write(c.transcript);
    }

    await fdZKey.close();
    await fdMPCParams.close();

    async function writeG1(P) {
        const buff = new Uint8Array(sG1);
        curve.G1.toRprUncompressed(buff, 0, P);
        await fdMPCParams.write(buff);
    }

    async function writeG2(P) {
        const buff = new Uint8Array(sG2);
        curve.G2.toRprUncompressed(buff, 0, P);
        await fdMPCParams.write(buff);
    }

    async function writePointArray(groupName, buff) {
        let sG;
        if (groupName == "G1") {
            sG = sG1;
        } else {
            sG = sG2;
        }

        const buffSize = new Uint8Array(4);
        const buffSizeV = new DataView(buffSize.buffer, buffSize.byteOffset, buffSize.byteLength);
        buffSizeV.setUint32(0, buff.byteLength / sG, false);

        await fdMPCParams.write(buffSize);
        await fdMPCParams.write(buff);
    }

    async function writeU32(n) {
        const buffSize = new Uint8Array(4);
        const buffSizeV = new DataView(buffSize.buffer, buffSize.byteOffset, buffSize.byteLength);
        buffSizeV.setUint32(0, n, false);

        await fdMPCParams.write(buffSize);
    }



}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function phase2importMPCParams(zkeyNameOld, mpcparamsName, zkeyNameNew, name, logger) {

    const {fd: fdZKeyOld, sections: sectionsZKeyOld} = await binFileUtils__namespace.readBinFile(zkeyNameOld, "zkey", 2);
    const zkeyHeader = await readHeader$1(fdZKeyOld, sectionsZKeyOld, false);
    if (zkeyHeader.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurveFromQ(zkeyHeader.q);
    const sG1 = curve.G1.F.n8*2;
    const sG2 = curve.G2.F.n8*2;

    const oldMPCParams = await readMPCParams(fdZKeyOld, curve, sectionsZKeyOld);
    const newMPCParams = {};

    const fdMPCParams = await fastFile__namespace.readExisting(mpcparamsName);

    fdMPCParams.pos =
        sG1*3 + sG2*3 +                     // vKey
        8 + sG1*zkeyHeader.nVars +              // IC + C
        4 + sG1*(zkeyHeader.domainSize-1) +     // H
        4 + sG1*zkeyHeader.nVars +              // A
        4 + sG1*zkeyHeader.nVars +              // B1
        4 + sG2*zkeyHeader.nVars;               // B2

    // csHash
    newMPCParams.csHash =  await fdMPCParams.read(64);

    const nConttributions = await fdMPCParams.readUBE32();
    newMPCParams.contributions = [];
    for (let i=0; i<nConttributions; i++) {
        const c = { delta:{} };
        c.deltaAfter = await readG1(fdMPCParams);
        c.delta.g1_s = await readG1(fdMPCParams);
        c.delta.g1_sx = await readG1(fdMPCParams);
        c.delta.g2_spx = await readG2(fdMPCParams);
        c.transcript = await fdMPCParams.read(64);
        if (i<oldMPCParams.contributions.length) {
            c.type = oldMPCParams.contributions[i].type;
            if (c.type==1) {
                c.beaconHash = oldMPCParams.contributions[i].beaconHash;
                c.numIterationsExp = oldMPCParams.contributions[i].numIterationsExp;
            }
            if (oldMPCParams.contributions[i].name) {
                c.name = oldMPCParams.contributions[i].name;
            }
        }
        newMPCParams.contributions.push(c);
    }

    if (!hashIsEqual(newMPCParams.csHash, oldMPCParams.csHash)) {
        if (logger) logger.error("Hash of the original circuit does not match with the MPC one");
        return false;
    }

    if (oldMPCParams.contributions.length > newMPCParams.contributions.length) {
        if (logger) logger.error("The impoerted file does not include new contributions");
        return false;
    }

    for (let i=0; i<oldMPCParams.contributions.length; i++) {
        if (!contributionIsEqual(oldMPCParams.contributions[i], newMPCParams.contributions[i])) {
            if (logger) logger.error(`Previos contribution ${i} does not match`);
            return false;
        }
    }


    // Set the same name to all new controbutions
    if (name) {
        for (let i=oldMPCParams.contributions.length; i<newMPCParams.contributions.length; i++) {
            newMPCParams.contributions[i].name = name;
        }
    }

    const fdZKeyNew = await binFileUtils__namespace.createBinFile(zkeyNameNew, "zkey", 1, 10);
    fdMPCParams.pos = 0;

    // Header
    fdMPCParams.pos += sG1;  // ignore alpha1 (keep original)
    fdMPCParams.pos += sG1;  // ignore beta1
    fdMPCParams.pos += sG2;  // ignore beta2
    fdMPCParams.pos += sG2;  // ignore gamma2
    zkeyHeader.vk_delta_1 = await readG1(fdMPCParams);
    zkeyHeader.vk_delta_2 = await readG2(fdMPCParams);
    await writeHeader(fdZKeyNew, zkeyHeader);

    // IC (Keep original)
    const nIC = await fdMPCParams.readUBE32();
    if (nIC != zkeyHeader.nPublic +1) {
        if (logger) logger.error("Invalid number of points in IC");
        await fdZKeyNew.discard();
        return false;
    }
    fdMPCParams.pos += sG1*(zkeyHeader.nPublic+1);
    await binFileUtils__namespace.copySection(fdZKeyOld, sectionsZKeyOld, fdZKeyNew, 3);

    // Coeffs (Keep original)
    await binFileUtils__namespace.copySection(fdZKeyOld, sectionsZKeyOld, fdZKeyNew, 4);

    // H Section
    const nH = await fdMPCParams.readUBE32();
    if (nH != zkeyHeader.domainSize-1) {
        if (logger) logger.error("Invalid number of points in H");
        await fdZKeyNew.discard();
        return false;
    }
    let buffH;
    const buffTauU = await fdMPCParams.read(sG1*(zkeyHeader.domainSize-1));
    const buffTauLEM = await curve.G1.batchUtoLEM(buffTauU);
    buffH = new Uint8Array(zkeyHeader.domainSize*sG1);
    buffH.set(buffTauLEM);   // Let the last one to zero.
    curve.G1.toRprLEM(buffH, sG1*(zkeyHeader.domainSize-1), curve.G1.zeroAffine);
    const n2Inv = curve.Fr.neg(curve.Fr.inv(curve.Fr.e(2)));
    const wInv = curve.Fr.inv(curve.Fr.w[zkeyHeader.power+1]);
    buffH = await curve.G1.batchApplyKey(buffH, n2Inv, wInv, "affine", "jacobian", logger);
    buffH = await curve.G1.ifft(buffH, "jacobian", "affine", logger);
    await binFileUtils__namespace.startWriteSection(fdZKeyNew, 9);
    await fdZKeyNew.write(buffH);
    await binFileUtils__namespace.endWriteSection(fdZKeyNew);

    // C Secion (L section)
    const nL = await fdMPCParams.readUBE32();
    if (nL != (zkeyHeader.nVars-zkeyHeader.nPublic-1)) {
        if (logger) logger.error("Invalid number of points in L");
        await fdZKeyNew.discard();
        return false;
    }
    let buffL;
    buffL = await fdMPCParams.read(sG1*(zkeyHeader.nVars-zkeyHeader.nPublic-1));
    buffL = await curve.G1.batchUtoLEM(buffL);
    await binFileUtils__namespace.startWriteSection(fdZKeyNew, 8);
    await fdZKeyNew.write(buffL);
    await binFileUtils__namespace.endWriteSection(fdZKeyNew);

    // A Section
    const nA = await fdMPCParams.readUBE32();
    if (nA != zkeyHeader.nVars) {
        if (logger) logger.error("Invalid number of points in A");
        await fdZKeyNew.discard();
        return false;
    }
    fdMPCParams.pos += sG1*(zkeyHeader.nVars);
    await binFileUtils__namespace.copySection(fdZKeyOld, sectionsZKeyOld, fdZKeyNew, 5);

    // B1 Section
    const nB1 = await fdMPCParams.readUBE32();
    if (nB1 != zkeyHeader.nVars) {
        if (logger) logger.error("Invalid number of points in B1");
        await fdZKeyNew.discard();
        return false;
    }
    fdMPCParams.pos += sG1*(zkeyHeader.nVars);
    await binFileUtils__namespace.copySection(fdZKeyOld, sectionsZKeyOld, fdZKeyNew, 6);

    // B2 Section
    const nB2 = await fdMPCParams.readUBE32();
    if (nB2 != zkeyHeader.nVars) {
        if (logger) logger.error("Invalid number of points in B2");
        await fdZKeyNew.discard();
        return false;
    }
    fdMPCParams.pos += sG2*(zkeyHeader.nVars);
    await binFileUtils__namespace.copySection(fdZKeyOld, sectionsZKeyOld, fdZKeyNew, 7);

    await writeMPCParams(fdZKeyNew, curve, newMPCParams);

    await fdMPCParams.close();
    await fdZKeyNew.close();
    await fdZKeyOld.close();

    return true;

    async function readG1(fd) {
        const buff = await fd.read(curve.G1.F.n8*2);
        return curve.G1.fromRprUncompressed(buff, 0);
    }

    async function readG2(fd) {
        const buff = await fd.read(curve.G2.F.n8*2);
        return curve.G2.fromRprUncompressed(buff, 0);
    }


    function contributionIsEqual(c1, c2) {
        if (!curve.G1.eq(c1.deltaAfter   , c2.deltaAfter)) return false;
        if (!curve.G1.eq(c1.delta.g1_s   , c2.delta.g1_s)) return false;
        if (!curve.G1.eq(c1.delta.g1_sx  , c2.delta.g1_sx)) return false;
        if (!curve.G2.eq(c1.delta.g2_spx , c2.delta.g2_spx)) return false;
        if (!hashIsEqual(c1.transcript, c2.transcript)) return false;
        return true;
    }


}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const sameRatio = sameRatio$2;



async function phase2verifyFromInit(initFileName, pTauFileName, zkeyFileName, logger) {

    let sr;
    await Blake2b__default["default"].ready();

    const {fd, sections} = await binFileUtils__namespace.readBinFile(zkeyFileName, "zkey", 2);
    const zkey = await readHeader$1(fd, sections, false);
    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurveFromQ(zkey.q);
    const sG1 = curve.G1.F.n8*2;

    const mpcParams = await readMPCParams(fd, curve, sections);

    const accumulatedHasher = Blake2b__default["default"](64);
    accumulatedHasher.update(mpcParams.csHash);
    let curDelta = curve.G1.g;
    for (let i=0; i<mpcParams.contributions.length; i++) {
        const c = mpcParams.contributions[i];
        const ourHasher = cloneHasher(accumulatedHasher);

        hashG1(ourHasher, curve, c.delta.g1_s);
        hashG1(ourHasher, curve, c.delta.g1_sx);

        if (!hashIsEqual(ourHasher.digest(), c.transcript)) {
            console.log(`INVALID(${i}): Inconsistent transcript `);
            return false;
        }

        const delta_g2_sp = hashToG2(curve, c.transcript);

        sr = await sameRatio(curve, c.delta.g1_s, c.delta.g1_sx, delta_g2_sp, c.delta.g2_spx);
        if (sr !== true) {
            console.log(`INVALID(${i}): public key G1 and G2 do not have the same ration `);
            return false;
        }

        sr = await sameRatio(curve, curDelta, c.deltaAfter, delta_g2_sp, c.delta.g2_spx);
        if (sr !== true) {
            console.log(`INVALID(${i}): deltaAfter does not fillow the public key `);
            return false;
        }

        if (c.type == 1) {
            const rng = rngFromBeaconParams(c.beaconHash, c.numIterationsExp);
            const expected_prvKey = curve.Fr.fromRng(rng);
            const expected_g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
            const expected_g1_sx = curve.G1.toAffine(curve.G1.timesFr(expected_g1_s, expected_prvKey));
            if (curve.G1.eq(expected_g1_s, c.delta.g1_s) !== true) {
                console.log(`INVALID(${i}): Key of the beacon does not match. g1_s `);
                return false;
            }
            if (curve.G1.eq(expected_g1_sx, c.delta.g1_sx) !== true) {
                console.log(`INVALID(${i}): Key of the beacon does not match. g1_sx `);
                return false;
            }
        }

        hashPubKey(accumulatedHasher, curve, c);

        const contributionHasher = Blake2b__default["default"](64);
        hashPubKey(contributionHasher, curve, c);

        c.contributionHash = contributionHasher.digest();

        curDelta = c.deltaAfter;
    }


    const {fd: fdInit, sections: sectionsInit} = await binFileUtils__namespace.readBinFile(initFileName, "zkey", 2);
    const zkeyInit = await readHeader$1(fdInit, sectionsInit, false);

    if (zkeyInit.protocol != "groth16") {
        throw new Error("zkeyinit file is not groth16");
    }

    if (  (!ffjavascript.Scalar.eq(zkeyInit.q, zkey.q))
        ||(!ffjavascript.Scalar.eq(zkeyInit.r, zkey.r))
        ||(zkeyInit.n8q != zkey.n8q)
        ||(zkeyInit.n8r != zkey.n8r))
    {
        if (logger) logger.error("INVALID:  Different curves");
        return false;
    }

    if (  (zkeyInit.nVars != zkey.nVars)
        ||(zkeyInit.nPublic !=  zkey.nPublic)
        ||(zkeyInit.domainSize != zkey.domainSize))
    {
        if (logger) logger.error("INVALID:  Different circuit parameters");
        return false;
    }

    if (!curve.G1.eq(zkey.vk_alpha_1, zkeyInit.vk_alpha_1)) {
        if (logger) logger.error("INVALID:  Invalid alpha1");
        return false;
    }
    if (!curve.G1.eq(zkey.vk_beta_1, zkeyInit.vk_beta_1)) {
        if (logger) logger.error("INVALID:  Invalid beta1");
        return false;
    }
    if (!curve.G2.eq(zkey.vk_beta_2, zkeyInit.vk_beta_2)) {
        if (logger) logger.error("INVALID:  Invalid beta2");
        return false;
    }
    if (!curve.G2.eq(zkey.vk_gamma_2, zkeyInit.vk_gamma_2)) {
        if (logger) logger.error("INVALID:  Invalid gamma2");
        return false;
    }
    if (!curve.G1.eq(zkey.vk_delta_1, curDelta)) {
        if (logger) logger.error("INVALID:  Invalid delta1");
        return false;
    }
    sr = await sameRatio(curve, curve.G1.g, curDelta, curve.G2.g, zkey.vk_delta_2);
    if (sr !== true) {
        if (logger) logger.error("INVALID:  Invalid delta2");
        return false;
    }

    const mpcParamsInit = await readMPCParams(fdInit, curve, sectionsInit);
    if (!hashIsEqual(mpcParams.csHash, mpcParamsInit.csHash)) {
        if (logger) logger.error("INVALID:  Circuit does not match");
        return false;
    }

    // Check sizes of sections
    if (sections[8][0].size != sG1*(zkey.nVars-zkey.nPublic-1)) {
        if (logger) logger.error("INVALID:  Invalid L section size");
        return false;
    }

    if (sections[9][0].size != sG1*(zkey.domainSize)) {
        if (logger) logger.error("INVALID:  Invalid H section size");
        return false;
    }

    let ss;
    ss = await binFileUtils__namespace.sectionIsEqual(fd, sections, fdInit, sectionsInit, 3);
    if (!ss) {
        if (logger) logger.error("INVALID:  IC section is not identical");
        return false;
    }

    ss = await binFileUtils__namespace.sectionIsEqual(fd, sections, fdInit, sectionsInit, 4);
    if (!ss) {
        if (logger) logger.error("Coeffs section is not identical");
        return false;
    }

    ss = await binFileUtils__namespace.sectionIsEqual(fd, sections, fdInit, sectionsInit, 5);
    if (!ss) {
        if (logger) logger.error("A section is not identical");
        return false;
    }

    ss = await binFileUtils__namespace.sectionIsEqual(fd, sections, fdInit, sectionsInit, 6);
    if (!ss) {
        if (logger) logger.error("B1 section is not identical");
        return false;
    }

    ss = await binFileUtils__namespace.sectionIsEqual(fd, sections, fdInit, sectionsInit, 7);
    if (!ss) {
        if (logger) logger.error("B2 section is not identical");
        return false;
    }

    // Check L
    sr = await sectionHasSameRatio("G1", fdInit, sectionsInit, fd, sections, 8, zkey.vk_delta_2, zkeyInit.vk_delta_2, "L section");
    if (sr!==true) {
        if (logger) logger.error("L section does not match");
        return false;
    }

    // Check H
    sr = await sameRatioH();
    if (sr!==true) {
        if (logger) logger.error("H section does not match");
        return false;
    }

    if (logger) logger.info(formatHash(mpcParams.csHash, "Circuit Hash: "));

    await fd.close();
    await fdInit.close();

    for (let i=mpcParams.contributions.length-1; i>=0; i--) {
        const c = mpcParams.contributions[i];
        if (logger) logger.info("-------------------------");
        if (logger) logger.info(formatHash(c.contributionHash, `contribution #${i+1} ${c.name ? c.name : ""}:`));
        if (c.type == 1) {
            if (logger) logger.info(`Beacon generator: ${byteArray2hex(c.beaconHash)}`);
            if (logger) logger.info(`Beacon iterations Exp: ${c.numIterationsExp}`);
        }
    }
    if (logger) logger.info("-------------------------");

    if (logger) logger.info("ZKey Ok!");

    return true;


    async function sectionHasSameRatio(groupName, fd1, sections1, fd2, sections2, idSection, g2sp, g2spx, sectionName) {
        const MAX_CHUNK_SIZE = 1<<20;
        const G = curve[groupName];
        const sG = G.F.n8*2;
        await binFileUtils__namespace.startReadUniqueSection(fd1, sections1, idSection);
        await binFileUtils__namespace.startReadUniqueSection(fd2, sections2, idSection);

        let R1 = G.zero;
        let R2 = G.zero;

        const nPoints = sections1[idSection][0].size / sG;

        for (let i=0; i<nPoints; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`Same ratio check ${sectionName}:  ${i}/${nPoints}`);
            const n = Math.min(nPoints - i, MAX_CHUNK_SIZE);
            const bases1 = await fd1.read(n*sG);
            const bases2 = await fd2.read(n*sG);

            const scalars = new Uint8Array(4*n);
            crypto__default["default"].randomFillSync(scalars);


            const r1 = await G.multiExpAffine(bases1, scalars);
            const r2 = await G.multiExpAffine(bases2, scalars);

            R1 = G.add(R1, r1);
            R2 = G.add(R2, r2);
        }
        await binFileUtils__namespace.endReadSection(fd1);
        await binFileUtils__namespace.endReadSection(fd2);

        if (nPoints == 0) return true;

        sr = await sameRatio(curve, R1, R2, g2sp, g2spx);
        if (sr !== true) return false;

        return true;
    }

    async function sameRatioH() {
        const MAX_CHUNK_SIZE = 1<<20;
        const G = curve.G1;
        const Fr = curve.Fr;
        const sG = G.F.n8*2;

        const {fd: fdPTau, sections: sectionsPTau} = await binFileUtils__namespace.readBinFile(pTauFileName, "ptau", 1);

        let buff_r = new ffjavascript.BigBuffer(zkey.domainSize * zkey.n8r);

        const seed= new Array(8);
        for (let i=0; i<8; i++) {
            seed[i] = crypto__default["default"].randomBytes(4).readUInt32BE(0, true);
        }
        const rng = new ffjavascript.ChaCha(seed);
        for (let i=0; i<zkey.domainSize-1; i++) {   // Note that last one is zero
            const e = Fr.fromRng(rng);
            Fr.toRprLE(buff_r, i*zkey.n8r, e);
        }
        Fr.toRprLE(buff_r, (zkey.domainSize-1)*zkey.n8r, Fr.zero);

        let R1 = G.zero;
        for (let i=0; i<zkey.domainSize; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`H Verificaition(tau):  ${i}/${zkey.domainSize}`);
            const n = Math.min(zkey.domainSize - i, MAX_CHUNK_SIZE);

            const buff1 = await fdPTau.read(sG*n, sectionsPTau[2][0].p + zkey.domainSize*sG + i*sG);
            const buff2 = await fdPTau.read(sG*n, sectionsPTau[2][0].p + i*sG);

            const buffB = await batchSubstract(buff1, buff2);
            const buffS = buff_r.slice(i*zkey.n8r, (i+n)*zkey.n8r);
            const r = await G.multiExpAffine(buffB, buffS);

            R1 = G.add(R1, r);
        }

        // Caluclate odd coeficients in transformed domain

        buff_r = await Fr.batchToMontgomery(buff_r);
        // const first = curve.Fr.neg(curve.Fr.inv(curve.Fr.e(2)));
        // Works*2   const first = curve.Fr.neg(curve.Fr.e(2));


        let first;

        if (zkey.power < Fr.s) {
            first = Fr.neg(Fr.e(2));
        } else {
            const small_m  = 2 ** Fr.s;
            const shift_to_small_m = Fr.exp(Fr.shift, small_m);
            first = Fr.sub( shift_to_small_m, Fr.one);
        }

        // const inc = curve.Fr.inv(curve.PFr.w[zkey.power+1]);
        const inc = zkey.power < Fr.s ? Fr.w[zkey.power+1] : Fr.shift;
        buff_r = await Fr.batchApplyKey(buff_r, first, inc);
        buff_r = await Fr.fft(buff_r);
        buff_r = await Fr.batchFromMontgomery(buff_r);

        await binFileUtils__namespace.startReadUniqueSection(fd, sections, 9);
        let R2 = G.zero;
        for (let i=0; i<zkey.domainSize; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`H Verificaition(lagrange):  ${i}/${zkey.domainSize}`);
            const n = Math.min(zkey.domainSize - i, MAX_CHUNK_SIZE);

            const buff = await fd.read(sG*n);
            const buffS = buff_r.slice(i*zkey.n8r, (i+n)*zkey.n8r);
            const r = await G.multiExpAffine(buff, buffS);

            R2 = G.add(R2, r);
        }
        await binFileUtils__namespace.endReadSection(fd);

        sr = await sameRatio(curve, R1, R2, zkey.vk_delta_2, zkeyInit.vk_delta_2);
        if (sr !== true) return false;


        return true;

    }

    async function batchSubstract(buff1, buff2) {
        const sG = curve.G1.F.n8*2;
        const nPoints = buff1.byteLength / sG;
        const concurrency= curve.tm.concurrency;
        const nPointsPerThread = Math.floor(nPoints / concurrency);
        const opPromises = [];
        for (let i=0; i<concurrency; i++) {
            let n;
            if (i< concurrency-1) {
                n = nPointsPerThread;
            } else {
                n = nPoints - i*nPointsPerThread;
            }
            if (n==0) continue;

            const subBuff1 = buff1.slice(i*nPointsPerThread*sG1, (i*nPointsPerThread+n)*sG1);
            const subBuff2 = buff2.slice(i*nPointsPerThread*sG1, (i*nPointsPerThread+n)*sG1);
            opPromises.push(batchSubstractThread(subBuff1, subBuff2));
        }


        const result = await Promise.all(opPromises);

        const fullBuffOut = new Uint8Array(nPoints*sG);
        let p =0;
        for (let i=0; i<result.length; i++) {
            fullBuffOut.set(result[i][0], p);
            p+=result[i][0].byteLength;
        }

        return fullBuffOut;
    }


    async function batchSubstractThread(buff1, buff2) {
        const sG1 = curve.G1.F.n8*2;
        const sGmid = curve.G1.F.n8*3;
        const nPoints = buff1.byteLength/sG1;
        const task = [];
        task.push({cmd: "ALLOCSET", var: 0, buff: buff1});
        task.push({cmd: "ALLOCSET", var: 1, buff: buff2});
        task.push({cmd: "ALLOC", var: 2, len: nPoints*sGmid});
        for (let i=0; i<nPoints; i++) {
            task.push({
                cmd: "CALL",
                fnName: "g1m_subAffine",
                params: [
                    {var: 0, offset: i*sG1},
                    {var: 1, offset: i*sG1},
                    {var: 2, offset: i*sGmid},
                ]
            });
        }
        task.push({cmd: "CALL", fnName: "g1m_batchToAffine", params: [
            {var: 2},
            {val: nPoints},
            {var: 2},
        ]});
        task.push({cmd: "GET", out: 0, var: 2, len: nPoints*sG1});

        const res = await curve.tm.queueAction(task);

        return res;
    }

}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function phase2verifyFromR1cs(r1csFileName, pTauFileName, zkeyFileName, logger) {

    // const initFileName = "~" + zkeyFileName + ".init";
    const initFileName = {type: "bigMem"};
    await newZKey(r1csFileName, pTauFileName, initFileName, logger);

    return await phase2verifyFromInit(initFileName, pTauFileName, zkeyFileName, logger);
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function phase2contribute(zkeyNameOld, zkeyNameNew, name, entropy, logger) {
    await Blake2b__default["default"].ready();

    const {fd: fdOld, sections: sections} = await binFileUtils__namespace.readBinFile(zkeyNameOld, "zkey", 2);
    const zkey = await readHeader$1(fdOld, sections);
    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurveFromQ(zkey.q);

    const mpcParams = await readMPCParams(fdOld, curve, sections);

    const fdNew = await binFileUtils__namespace.createBinFile(zkeyNameNew, "zkey", 1, 10);


    const rng = await getRandomRng(entropy);

    const transcriptHasher = Blake2b__default["default"](64);
    transcriptHasher.update(mpcParams.csHash);
    for (let i=0; i<mpcParams.contributions.length; i++) {
        hashPubKey(transcriptHasher, curve, mpcParams.contributions[i]);
    }

    const curContribution = {};
    curContribution.delta = {};
    curContribution.delta.prvKey = curve.Fr.fromRng(rng);
    curContribution.delta.g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
    curContribution.delta.g1_sx = curve.G1.toAffine(curve.G1.timesFr(curContribution.delta.g1_s, curContribution.delta.prvKey));
    hashG1(transcriptHasher, curve, curContribution.delta.g1_s);
    hashG1(transcriptHasher, curve, curContribution.delta.g1_sx);
    curContribution.transcript = transcriptHasher.digest();
    curContribution.delta.g2_sp = hashToG2(curve, curContribution.transcript);
    curContribution.delta.g2_spx = curve.G2.toAffine(curve.G2.timesFr(curContribution.delta.g2_sp, curContribution.delta.prvKey));

    zkey.vk_delta_1 = curve.G1.timesFr(zkey.vk_delta_1, curContribution.delta.prvKey);
    zkey.vk_delta_2 = curve.G2.timesFr(zkey.vk_delta_2, curContribution.delta.prvKey);

    curContribution.deltaAfter = zkey.vk_delta_1;

    curContribution.type = 0;
    if (name) curContribution.name = name;

    mpcParams.contributions.push(curContribution);

    await writeHeader(fdNew, zkey);

    // IC
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 3);

    // Coeffs (Keep original)
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 4);

    // A Section
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 5);

    // B1 Section
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 6);

    // B2 Section
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 7);

    const invDelta = curve.Fr.inv(curContribution.delta.prvKey);
    await applyKeyToSection(fdOld, sections, fdNew, 8, curve, "G1", invDelta, curve.Fr.e(1), "L Section", logger);
    await applyKeyToSection(fdOld, sections, fdNew, 9, curve, "G1", invDelta, curve.Fr.e(1), "H Section", logger);

    await writeMPCParams(fdNew, curve, mpcParams);

    await fdOld.close();
    await fdNew.close();

    const contributionHasher = Blake2b__default["default"](64);
    hashPubKey(contributionHasher, curve, curContribution);

    const contribuionHash = contributionHasher.digest();

    if (logger) logger.info(formatHash(mpcParams.csHash, "Circuit Hash: "));
    if (logger) logger.info(formatHash(contribuionHash, "Contribution Hash: "));

    return contribuionHash;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/


async function beacon(zkeyNameOld, zkeyNameNew, name, beaconHashStr, numIterationsExp, logger) {
    await Blake2b__default["default"].ready();

    const beaconHash = hex2ByteArray(beaconHashStr);
    if (   (beaconHash.byteLength == 0)
        || (beaconHash.byteLength*2 !=beaconHashStr.length))
    {
        if (logger) logger.error("Invalid Beacon Hash. (It must be a valid hexadecimal sequence)");
        return false;
    }
    if (beaconHash.length>=256) {
        if (logger) logger.error("Maximum lenght of beacon hash is 255 bytes");
        return false;
    }

    numIterationsExp = parseInt(numIterationsExp);
    if ((numIterationsExp<10)||(numIterationsExp>63)) {
        if (logger) logger.error("Invalid numIterationsExp. (Must be between 10 and 63)");
        return false;
    }


    const {fd: fdOld, sections: sections} = await binFileUtils__namespace.readBinFile(zkeyNameOld, "zkey", 2);
    const zkey = await readHeader$1(fdOld, sections);

    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }


    const curve = await getCurveFromQ(zkey.q);

    const mpcParams = await readMPCParams(fdOld, curve, sections);

    const fdNew = await binFileUtils__namespace.createBinFile(zkeyNameNew, "zkey", 1, 10);

    const rng = await rngFromBeaconParams(beaconHash, numIterationsExp);

    const transcriptHasher = Blake2b__default["default"](64);
    transcriptHasher.update(mpcParams.csHash);
    for (let i=0; i<mpcParams.contributions.length; i++) {
        hashPubKey(transcriptHasher, curve, mpcParams.contributions[i]);
    }

    const curContribution = {};
    curContribution.delta = {};
    curContribution.delta.prvKey = curve.Fr.fromRng(rng);
    curContribution.delta.g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
    curContribution.delta.g1_sx = curve.G1.toAffine(curve.G1.timesFr(curContribution.delta.g1_s, curContribution.delta.prvKey));
    hashG1(transcriptHasher, curve, curContribution.delta.g1_s);
    hashG1(transcriptHasher, curve, curContribution.delta.g1_sx);
    curContribution.transcript = transcriptHasher.digest();
    curContribution.delta.g2_sp = hashToG2(curve, curContribution.transcript);
    curContribution.delta.g2_spx = curve.G2.toAffine(curve.G2.timesFr(curContribution.delta.g2_sp, curContribution.delta.prvKey));

    zkey.vk_delta_1 = curve.G1.timesFr(zkey.vk_delta_1, curContribution.delta.prvKey);
    zkey.vk_delta_2 = curve.G2.timesFr(zkey.vk_delta_2, curContribution.delta.prvKey);

    curContribution.deltaAfter = zkey.vk_delta_1;

    curContribution.type = 1;
    curContribution.numIterationsExp = numIterationsExp;
    curContribution.beaconHash = beaconHash;

    if (name) curContribution.name = name;

    mpcParams.contributions.push(curContribution);

    await writeHeader(fdNew, zkey);

    // IC
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 3);

    // Coeffs (Keep original)
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 4);

    // A Section
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 5);

    // B1 Section
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 6);

    // B2 Section
    await binFileUtils__namespace.copySection(fdOld, sections, fdNew, 7);

    const invDelta = curve.Fr.inv(curContribution.delta.prvKey);
    await applyKeyToSection(fdOld, sections, fdNew, 8, curve, "G1", invDelta, curve.Fr.e(1), "L Section", logger);
    await applyKeyToSection(fdOld, sections, fdNew, 9, curve, "G1", invDelta, curve.Fr.e(1), "H Section", logger);

    await writeMPCParams(fdNew, curve, mpcParams);

    await fdOld.close();
    await fdNew.close();

    const contributionHasher = Blake2b__default["default"](64);
    hashPubKey(contributionHasher, curve, curContribution);

    const contribuionHash = contributionHasher.digest();

    if (logger) logger.info(formatHash(contribuionHash, "Contribution Hash: "));

    return contribuionHash;
}

async function zkeyExportJson(zkeyFileName) {

    const zKey = await readZKey(zkeyFileName, true);
    delete zKey.curve;
    delete zKey.F;

    return ffjavascript.utils.stringifyBigInts(zKey);
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

async function bellmanContribute(curve, challengeFilename, responesFileName, entropy, logger) {
    await Blake2b__default["default"].ready();

    const rng = await getRandomRng(entropy);

    const delta = curve.Fr.fromRng(rng);
    const invDelta = curve.Fr.inv(delta);

    const sG1 = curve.G1.F.n8*2;
    const sG2 = curve.G2.F.n8*2;

    const fdFrom = await fastFile__namespace.readExisting(challengeFilename);
    const fdTo = await fastFile__namespace.createOverride(responesFileName);


    await copy(sG1); // alpha1
    await copy(sG1); // beta1
    await copy(sG2); // beta2
    await copy(sG2); // gamma2
    const oldDelta1 = await readG1();
    const delta1 = curve.G1.timesFr(oldDelta1, delta);
    await writeG1(delta1);
    const oldDelta2 = await readG2();
    const delta2 = curve.G2.timesFr(oldDelta2, delta);
    await writeG2(delta2);

    // IC
    const nIC = await fdFrom.readUBE32();
    await fdTo.writeUBE32(nIC);
    await copy(nIC*sG1);

    // H
    const nH = await fdFrom.readUBE32();
    await fdTo.writeUBE32(nH);
    await applyKeyToChallengeSection(fdFrom, fdTo, null, curve, "G1", nH, invDelta, curve.Fr.e(1), "UNCOMPRESSED", "H", logger);

    // L
    const nL = await fdFrom.readUBE32();
    await fdTo.writeUBE32(nL);
    await applyKeyToChallengeSection(fdFrom, fdTo, null, curve, "G1", nL, invDelta, curve.Fr.e(1), "UNCOMPRESSED", "L", logger);

    // A
    const nA = await fdFrom.readUBE32();
    await fdTo.writeUBE32(nA);
    await copy(nA*sG1);

    // B1
    const nB1 = await fdFrom.readUBE32();
    await fdTo.writeUBE32(nB1);
    await copy(nB1*sG1);

    // B2
    const nB2 = await fdFrom.readUBE32();
    await fdTo.writeUBE32(nB2);
    await copy(nB2*sG2);


    //////////
    /// Read contributions
    //////////
    const transcriptHasher = Blake2b__default["default"](64);

    const mpcParams = {};
    // csHash
    mpcParams.csHash =  await fdFrom.read(64);
    transcriptHasher.update(mpcParams.csHash);

    const nConttributions = await fdFrom.readUBE32();
    mpcParams.contributions = [];
    for (let i=0; i<nConttributions; i++) {
        const c = { delta:{} };
        c.deltaAfter = await readG1();
        c.delta.g1_s = await readG1();
        c.delta.g1_sx = await readG1();
        c.delta.g2_spx = await readG2();
        c.transcript = await fdFrom.read(64);
        mpcParams.contributions.push(c);
        hashPubKey(transcriptHasher, curve, c);
    }

    const curContribution = {};
    curContribution.delta = {};
    curContribution.delta.prvKey = delta;
    curContribution.delta.g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
    curContribution.delta.g1_sx = curve.G1.toAffine(curve.G1.timesFr(curContribution.delta.g1_s, delta));
    hashG1(transcriptHasher, curve, curContribution.delta.g1_s);
    hashG1(transcriptHasher, curve, curContribution.delta.g1_sx);
    curContribution.transcript = transcriptHasher.digest();
    curContribution.delta.g2_sp = hashToG2(curve, curContribution.transcript);
    curContribution.delta.g2_spx = curve.G2.toAffine(curve.G2.timesFr(curContribution.delta.g2_sp, delta));
    curContribution.deltaAfter = delta1;
    curContribution.type = 0;
    mpcParams.contributions.push(curContribution);


    //////////
    /// Write COntribution
    //////////

    await fdTo.write(mpcParams.csHash);
    await fdTo.writeUBE32(mpcParams.contributions.length);

    for (let i=0; i<mpcParams.contributions.length; i++) {
        const c = mpcParams.contributions[i];
        await writeG1(c.deltaAfter);
        await writeG1(c.delta.g1_s);
        await writeG1(c.delta.g1_sx);
        await writeG2(c.delta.g2_spx);
        await fdTo.write(c.transcript);
    }

    const contributionHasher = Blake2b__default["default"](64);
    hashPubKey(contributionHasher, curve, curContribution);

    const contributionHash = contributionHasher.digest();

    if (logger) logger.info(formatHash(contributionHash, "Contribution Hash: "));

    await fdTo.close();
    await fdFrom.close();

    return contributionHash;

    async function copy(nBytes) {
        const CHUNK_SIZE = fdFrom.pageSize*2;
        for (let i=0; i<nBytes; i+= CHUNK_SIZE) {
            const n = Math.min(nBytes -i, CHUNK_SIZE);
            const buff = await fdFrom.read(n);
            await fdTo.write(buff);
        }
    }

    async function readG1() {
        const buff = await fdFrom.read(curve.G1.F.n8*2);
        return curve.G1.fromRprUncompressed(buff, 0);
    }

    async function readG2() {
        const buff = await fdFrom.read(curve.G2.F.n8*2);
        return curve.G2.fromRprUncompressed(buff, 0);
    }

    async function writeG1(P) {
        const buff = new Uint8Array(sG1);
        curve.G1.toRprUncompressed(buff, 0, P);
        await fdTo.write(buff);
    }

    async function writeG2(P) {
        const buff = new Uint8Array(sG2);
        curve.G2.toRprUncompressed(buff, 0, P);
        await fdTo.write(buff);
    }


}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const {stringifyBigInts: stringifyBigInts$1} = ffjavascript.utils;

async function zkeyExportVerificationKey(zkeyName, /* logger */ ) {

    const {fd, sections} = await binFileUtils__namespace.readBinFile(zkeyName, "zkey", 2);
    const zkey = await readHeader$1(fd, sections);

    let res;
    if (zkey.protocol == "groth16") {
        res = await groth16Vk(zkey, fd, sections);
    } else if (zkey.protocol == "plonk") {
        res = await plonkVk(zkey);
    } else {
        throw new Error("zkey file is not groth16");
    }

    await fd.close();

    return res;
}


async function groth16Vk(zkey, fd, sections) {
    const curve = await getCurveFromQ(zkey.q);
    const sG1 = curve.G1.F.n8*2;

    const alphaBeta = await curve.pairing( zkey.vk_alpha_1 , zkey.vk_beta_2 );

    let vKey = {
        protocol: zkey.protocol,
        curve: curve.name,
        nPublic: zkey.nPublic,

        vk_alpha_1: curve.G1.toObject(zkey.vk_alpha_1),

        vk_beta_2: curve.G2.toObject(zkey.vk_beta_2),
        vk_gamma_2:  curve.G2.toObject(zkey.vk_gamma_2),
        vk_delta_2:  curve.G2.toObject(zkey.vk_delta_2),

        vk_alphabeta_12: curve.Gt.toObject(alphaBeta)
    };

    // Read IC Section
    ///////////
    await binFileUtils__namespace.startReadUniqueSection(fd, sections, 3);
    vKey.IC = [];
    for (let i=0; i<= zkey.nPublic; i++) {
        const buff = await fd.read(sG1);
        const P = curve.G1.toObject(buff);
        vKey.IC.push(P);
    }
    await binFileUtils__namespace.endReadSection(fd);

    vKey = stringifyBigInts$1(vKey);

    return vKey;
}


async function plonkVk(zkey) {
    const curve = await getCurveFromQ(zkey.q);

    let vKey = {
        protocol: zkey.protocol,
        curve: curve.name,
        nPublic: zkey.nPublic,
        power: zkey.power,

        k1: curve.Fr.toObject(zkey.k1),
        k2: curve.Fr.toObject(zkey.k2),

        Qm: curve.G1.toObject(zkey.Qm),
        Ql: curve.G1.toObject(zkey.Ql),
        Qr: curve.G1.toObject(zkey.Qr),
        Qo: curve.G1.toObject(zkey.Qo),
        Qc: curve.G1.toObject(zkey.Qc),
        S1: curve.G1.toObject(zkey.S1),
        S2: curve.G1.toObject(zkey.S2),
        S3: curve.G1.toObject(zkey.S3),

        X_2: curve.G2.toObject(zkey.X_2),

        w: curve.Fr.toObject(curve.Fr.w[zkey.power])
    };

    vKey = stringifyBigInts$1(vKey);

    return vKey;
}

// Not ready yet
// module.exports.generateVerifier_kimleeoh = generateVerifier_kimleeoh;



async function exportSolidityVerifier(zKeyName, templates, logger) {

    const verificationKey = await zkeyExportVerificationKey(zKeyName);

    let template = templates[verificationKey.protocol];

    return ejs__default["default"].render(template ,  verificationKey);
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

var zkey = /*#__PURE__*/Object.freeze({
    __proto__: null,
    newZKey: newZKey,
    exportBellman: phase2exportMPCParams,
    importBellman: phase2importMPCParams,
    verifyFromR1cs: phase2verifyFromR1cs,
    verifyFromInit: phase2verifyFromInit,
    contribute: phase2contribute,
    beacon: beacon,
    exportJson: zkeyExportJson,
    bellmanContribute: bellmanContribute,
    exportVerificationKey: zkeyExportVerificationKey,
    exportSolidityVerifier: exportSolidityVerifier
});

/*
    Copyright 2021 0kims association.

    This file is part of snarkjs.

    snarkjs is a free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License as published by the
    Free Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    snarkjs is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    snarkjs. If not, see <https://www.gnu.org/licenses/>.
*/

async function plonkSetup(r1csName, ptauName, zkeyName, logger) {
	if (globalThis.gc) {
		globalThis.gc();
	}

	await Blake2b__default["default"].ready();

	const { fd: fdPTau, sections: sectionsPTau } = await binFileUtils.readBinFile(
		ptauName,
		"ptau",
		1,
		1 << 22,
		1 << 24
	);
	const { curve, power } = await readPTauHeader(fdPTau, sectionsPTau);
	const { fd: fdR1cs, sections: sectionsR1cs } = await binFileUtils.readBinFile(
		r1csName,
		"r1cs",
		1,
		1 << 22,
		1 << 24
	);
	const r1cs = await r1csfile.readR1csHeader(fdR1cs, sectionsR1cs, false);

	const sG1 = curve.G1.F.n8 * 2;
	const G1 = curve.G1;
	const sG2 = curve.G2.F.n8 * 2;
	const Fr = curve.Fr;
	const n8r = curve.Fr.n8;

	if (logger) logger.info("Reading r1cs");
	let sR1cs = await binFileUtils.readSection(fdR1cs, sectionsR1cs, 2);

	const plonkConstraints = new BigArray();
	const plonkAdditions = new BigArray();
	let plonkNVars = r1cs.nVars;

	const nPublic = r1cs.nOutputs + r1cs.nPubInputs;

	await processConstraints();
	if (globalThis.gc) {
		globalThis.gc();
	}

	const fdZKey = await binFileUtils.createBinFile(
		zkeyName,
		"zkey",
		1,
		14,
		1 << 22,
		1 << 24
	);

	if (r1cs.prime != curve.r) {
		if (logger)
			logger.error(
				"r1cs curve does not match powers of tau ceremony curve"
			);
		return -1;
	}

	let cirPower = log2(plonkConstraints.length - 1) + 1;
	if (cirPower < 3) cirPower = 3; // As the t polinomal is n+5 whe need at least a power of 4
	const domainSize = 2 ** cirPower;

	if (logger) logger.info("Plonk constraints: " + plonkConstraints.length);
	if (cirPower > power) {
		if (logger)
			logger.error(
				`circuit too big for this power of tau ceremony. ${plonkConstraints.length} > 2**${power}`
			);
		return -1;
	}

	if (!sectionsPTau[12]) {
		if (logger) logger.error("Powers of tau is not prepared.");
		return -1;
	}

	const LPoints = new ffjavascript.BigBuffer(domainSize * sG1);
	const o = sectionsPTau[12][0].p + (2 ** cirPower - 1) * sG1;
	await fdPTau.readToBuffer(LPoints, 0, domainSize * sG1, o);

	const [k1, k2] = getK1K2();

	const vk = {};

	await writeAdditions(3, "Additions");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeWitnessMap(4, 0, "Amap");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeWitnessMap(5, 1, "Bmap");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeWitnessMap(6, 2, "Cmap");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeQMap(7, 3, "Qm");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeQMap(8, 4, "Ql");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeQMap(9, 5, "Qr");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeQMap(10, 6, "Qo");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeQMap(11, 7, "Qc");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeSigma(12, "sigma");
	if (globalThis.gc) {
		globalThis.gc();
	}
	await writeLs(13, "lagrange polynomials");
	if (globalThis.gc) {
		globalThis.gc();
	}

	// Write PTau points
	////////////

	await binFileUtils.startWriteSection(fdZKey, 14);
	const buffOut = new ffjavascript.BigBuffer((domainSize + 6) * sG1);
	await fdPTau.readToBuffer(
		buffOut,
		0,
		(domainSize + 6) * sG1,
		sectionsPTau[2][0].p
	);
	await fdZKey.write(buffOut);
	await binFileUtils.endWriteSection(fdZKey);
	if (globalThis.gc) {
		globalThis.gc();
	}

	await writeHeaders();

	await fdZKey.close();
	await fdR1cs.close();
	await fdPTau.close();

	if (logger) logger.info("Setup Finished");

	return;

	async function processConstraints() {
		let r1csPos = 0;

		function r1cs_readULE32() {
			const buff = sR1cs.slice(r1csPos, r1csPos + 4);
			r1csPos += 4;
			const buffV = new DataView(buff.buffer);
			return buffV.getUint32(0, true);
		}

		function r1cs_readCoef() {
			const res = Fr.fromRprLE(
				sR1cs.slice(r1csPos, r1csPos + curve.Fr.n8)
			);
			r1csPos += curve.Fr.n8;
			return res;
		}

		// reads single constraint's either A, B, or C
		function r1cs_readCoefs() {
			const coefs = [];
			const res = {
				k: curve.Fr.zero,
			};
			// number of wires
			const nA = r1cs_readULE32();

			for (let i = 0; i < nA; i++) {
				// wireid
				const s = r1cs_readULE32();
				// coefficient
				const coefp = r1cs_readCoef();

				if (s == 0) {
					res.k = coefp;
				} else {
					coefs.push([s, coefp]);
				}
			}

			const resCoef = reduceCoef(coefs);
			res.s = resCoef[0];
			res.coef = resCoef[1];
			return res;
		}

		function reduceCoef(coefs) {
			if (coefs.length == 0) {
				return [0, curve.Fr.zero];
			}
			if (coefs.length == 1) {
				return coefs[0];
			}
			const arr1 = coefs.slice(0, coefs.length >> 1);
			const arr2 = coefs.slice(coefs.length >> 1);
			const coef1 = reduceCoef(arr1);
			const coef2 = reduceCoef(arr2);

			const sl = coef1[0];
			const sr = coef2[0];
			const so = plonkNVars++;
			const qm = curve.Fr.zero;
			const ql = Fr.neg(coef1[1]);
			const qr = Fr.neg(coef2[1]);
			const qo = curve.Fr.one;
			const qc = curve.Fr.zero;

			plonkConstraints.push([sl, sr, so, qm, ql, qr, qo, qc]);

			plonkAdditions.push([sl, sr, coef1[1], coef2[1]]);

			return [so, curve.Fr.one];
		}

		for (let s = 1; s <= nPublic; s++) {
			const sl = s;
			const sr = 0;
			const so = 0;
			const qm = curve.Fr.zero;
			const ql = curve.Fr.one;
			const qr = curve.Fr.zero;
			const qo = curve.Fr.zero;
			const qc = curve.Fr.zero;

			plonkConstraints.push([sl, sr, so, qm, ql, qr, qo, qc]);
		}

		for (let c = 0; c < r1cs.nConstraints; c++) {
			if (logger && c % 10000 == 0)
				logger.debug(
					`processing constraints: ${c}/${r1cs.nConstraints}`
				);

			const A = r1cs_readCoefs();
			const B = r1cs_readCoefs();
			const C = r1cs_readCoefs();

			const sl = A.s;
			const sr = B.s;
			const so = C.s;
			const qm = curve.Fr.mul(A.coef, B.coef);
			const ql = curve.Fr.mul(A.coef, B.k);
			const qr = curve.Fr.mul(A.k, B.coef);
			const qo = curve.Fr.neg(C.coef);
			const qc = curve.Fr.sub(curve.Fr.mul(A.k, B.k), C.k);

			plonkConstraints.push([sl, sr, so, qm, ql, qr, qo, qc]);
		}
	}

	async function writeWitnessMap(sectionNum, posConstraint, name) {
		await binFileUtils.startWriteSection(fdZKey, sectionNum);
		for (let i = 0; i < plonkConstraints.length; i++) {
			await fdZKey.writeULE32(plonkConstraints[i][posConstraint]);
			if (logger && i % 1000000 == 0)
				logger.debug(
					`writing ${name}: ${i}/${plonkConstraints.length}`
				);
		}
		await binFileUtils.endWriteSection(fdZKey);
	}

	async function writeQMap(sectionNum, posConstraint, name) {
		let Q = new ffjavascript.BigBuffer(domainSize * n8r);
		for (let i = 0; i < plonkConstraints.length; i++) {
			Q.set(plonkConstraints[i][posConstraint], i * n8r);
			if (logger && i % 1000000 == 0)
				logger.debug(
					`writing ${name}: ${i}/${plonkConstraints.length}`
				);
		}
		await binFileUtils.startWriteSection(fdZKey, sectionNum);
		await writeP4(Q);
		await binFileUtils.endWriteSection(fdZKey);
		Q = await Fr.batchFromMontgomery(Q);
		vk[name] = await curve.G1.multiExpAffine(
			LPoints,
			Q,
			logger,
			"multiexp " + name
		);
	}

	async function writeP4(buff) {
		const q = await Fr.ifft(buff);
		const q4 = new ffjavascript.BigBuffer(domainSize * n8r * 4);
		q4.set(q, 0);
		const Q4 = await Fr.fft(q4);
		await fdZKey.write(q);
		await fdZKey.write(Q4);
	}

	async function writeAdditions(sectionNum, name) {
		await binFileUtils.startWriteSection(fdZKey, sectionNum);
		const buffOut = new Uint8Array(2 * 4 + 2 * n8r);
		const buffOutV = new DataView(buffOut.buffer);
		for (let i = 0; i < plonkAdditions.length; i++) {
			const addition = plonkAdditions[i];
			let o = 0;
			buffOutV.setUint32(o, addition[0], true);
			o += 4;
			buffOutV.setUint32(o, addition[1], true);
			o += 4;
			// The value is storen in  Montgomery. stored = v*R
			// so when montgomery multiplicated by the witness  it result = v*R*w/R = v*w
			buffOut.set(addition[2], o);
			o += n8r;
			buffOut.set(addition[3], o);
			o += n8r;
			await fdZKey.write(buffOut);
			if (logger && i % 1000000 == 0)
				logger.debug(`writing ${name}: ${i}/${plonkAdditions.length}`);
		}
		await binFileUtils.endWriteSection(fdZKey);
	}

	async function writeSigma(sectionNum, name) {
		const sigma = new ffjavascript.BigBuffer(n8r * domainSize * 3);
		const lastAparence = new BigArray(plonkNVars);
		const firstPos = new BigArray(plonkNVars);
		let w = Fr.one;
		for (let i = 0; i < domainSize; i++) {
			if (i < plonkConstraints.length) {
				buildSigma(plonkConstraints[i][0], i);
				buildSigma(plonkConstraints[i][1], domainSize + i);
				buildSigma(plonkConstraints[i][2], domainSize * 2 + i);
			} else {
				buildSigma(0, i);
				buildSigma(0, domainSize + i);
				buildSigma(0, domainSize * 2 + i);
			}
			w = Fr.mul(w, Fr.w[cirPower]);
			if (logger && i % 1000000 == 0)
				logger.debug(
					`writing ${name} phase1: ${i}/${plonkConstraints.length}`
				);
		}
		for (let s = 0; s < plonkNVars; s++) {
			if (typeof firstPos[s] !== "undefined") {
				sigma.set(lastAparence[s], firstPos[s] * n8r);
			} else {
				// throw new Error("Variable not used");
				console.log("Variable not used");
			}
			if (logger && s % 1000000 == 0)
				logger.debug(`writing ${name} phase2: ${s}/${plonkNVars}`);
		}

		if (globalThis.gc) {
			globalThis.gc();
		}
		await binFileUtils.startWriteSection(fdZKey, sectionNum);
		let S1 = sigma.slice(0, domainSize * n8r);
		await writeP4(S1);
		if (globalThis.gc) {
			globalThis.gc();
		}
		let S2 = sigma.slice(domainSize * n8r, domainSize * n8r * 2);
		await writeP4(S2);
		if (globalThis.gc) {
			globalThis.gc();
		}
		let S3 = sigma.slice(domainSize * n8r * 2, domainSize * n8r * 3);
		await writeP4(S3);
		if (globalThis.gc) {
			globalThis.gc();
		}
		await binFileUtils.endWriteSection(fdZKey);

		S1 = await Fr.batchFromMontgomery(S1);
		S2 = await Fr.batchFromMontgomery(S2);
		S3 = await Fr.batchFromMontgomery(S3);

		vk.S1 = await curve.G1.multiExpAffine(
			LPoints,
			S1,
			logger,
			"multiexp S1"
		);
		if (globalThis.gc) {
			globalThis.gc();
		}
		vk.S2 = await curve.G1.multiExpAffine(
			LPoints,
			S2,
			logger,
			"multiexp S2"
		);
		if (globalThis.gc) {
			globalThis.gc();
		}
		vk.S3 = await curve.G1.multiExpAffine(
			LPoints,
			S3,
			logger,
			"multiexp S3"
		);
		if (globalThis.gc) {
			globalThis.gc();
		}

		function buildSigma(s, p) {
			if (typeof lastAparence[s] === "undefined") {
				firstPos[s] = p;
			} else {
				sigma.set(lastAparence[s], p * n8r);
			}
			let v;
			if (p < domainSize) {
				v = w;
			} else if (p < 2 * domainSize) {
				v = Fr.mul(w, k1);
			} else {
				v = Fr.mul(w, k2);
			}
			lastAparence[s] = v;
		}
	}

	async function writeLs(sectionNum, name) {
		await binFileUtils.startWriteSection(fdZKey, sectionNum);
		const l = Math.max(nPublic, 1);
		for (let i = 0; i < l; i++) {
			let buff = new ffjavascript.BigBuffer(domainSize * n8r);
			buff.set(Fr.one, i * n8r);
			await writeP4(buff);
			if (logger) logger.debug(`writing ${name} ${i}/${l}`);
		}
		await binFileUtils.endWriteSection(fdZKey);
	}

	async function writeHeaders() {
		// Write the header
		///////////
		await binFileUtils.startWriteSection(fdZKey, 1);
		await fdZKey.writeULE32(2); // Plonk
		await binFileUtils.endWriteSection(fdZKey);

		// Write the Plonk header section
		///////////

		await binFileUtils.startWriteSection(fdZKey, 2);
		const primeQ = curve.q;
		const n8q = (Math.floor((ffjavascript.Scalar.bitLength(primeQ) - 1) / 64) + 1) * 8;

		const primeR = curve.r;
		const n8r = (Math.floor((ffjavascript.Scalar.bitLength(primeR) - 1) / 64) + 1) * 8;

		await fdZKey.writeULE32(n8q);
		await binFileUtils.writeBigInt(fdZKey, primeQ, n8q);
		await fdZKey.writeULE32(n8r);
		await binFileUtils.writeBigInt(fdZKey, primeR, n8r);
		await fdZKey.writeULE32(plonkNVars); // Total number of bars
		await fdZKey.writeULE32(nPublic); // Total number of public vars (not including ONE)
		await fdZKey.writeULE32(domainSize); // domainSize
		await fdZKey.writeULE32(plonkAdditions.length); // domainSize
		await fdZKey.writeULE32(plonkConstraints.length);

		await fdZKey.write(k1);
		await fdZKey.write(k2);

		await fdZKey.write(G1.toAffine(vk.Qm));
		await fdZKey.write(G1.toAffine(vk.Ql));
		await fdZKey.write(G1.toAffine(vk.Qr));
		await fdZKey.write(G1.toAffine(vk.Qo));
		await fdZKey.write(G1.toAffine(vk.Qc));

		await fdZKey.write(G1.toAffine(vk.S1));
		await fdZKey.write(G1.toAffine(vk.S2));
		await fdZKey.write(G1.toAffine(vk.S3));

		let bX_2;
		bX_2 = await fdPTau.read(sG2, sectionsPTau[3][0].p + sG2);
		await fdZKey.write(bX_2);

		await binFileUtils.endWriteSection(fdZKey);
	}

	function getK1K2() {
		let k1 = Fr.two;
		while (isIncluded(k1, [], cirPower)) Fr.add(k1, Fr.one);
		let k2 = Fr.add(k1, Fr.one);
		while (isIncluded(k2, [k1], cirPower)) Fr.add(k2, Fr.one);
		return [k1, k2];

		function isIncluded(k, kArr, pow) {
			const domainSize = 2 ** pow;
			let w = Fr.one;
			for (let i = 0; i < domainSize; i++) {
				if (Fr.eq(k, w)) return true;
				for (let j = 0; j < kArr.length; j++) {
					if (Fr.eq(k, Fr.mul(kArr[j], w))) return true;
				}
				w = Fr.mul(w, Fr.w[pow]);
			}
			return false;
		}
	}
}

class Transcript {
	constructor(rawJsonSpec, curve) {
		this.rawJsonSpec = rawJsonSpec;
		this.curve = curve;
		this.Fr = curve.Fr;
		this.F1 = curve.F1;
		this.G1 = curve.G1;

		// hasher
		this.poseidon = new poseidonJs.Poseidon(rawJsonSpec, this.curve);
	}

	load() {
		this.poseidon.parseSpec();
		this.poseidon.loadState();
	}

	// Scalar is a Field element in field Fr
	writeScalar(scalar, tag) {
		// console.log(`Writing scalar ${tag}: ${this.Fr.toString(scalar, 16)}`);
		this.poseidon.update([scalar]);
	}

	// Point in on curve G1
	writePoint(point, tag) {
		let [x, y] = [this.G1.x(point), this.G1.y(point)].map((v) => {
			let modFr = BigInt(
				"21888242871839275222246405745257275088548364400416034343698204186575808495617"
			);

			v = BigInt(this.F1.toString(v, 10));
			v = v % modFr;
			return this.Fr.fromRprLE(ffjavascript.utils.leInt2Buff(v));
		});

		// console.log(`Writing point ${tag}: x=${x}, y=${y}`);
		this.poseidon.update([x, y]);
	}

	// squeeze challenge
	squeezeChallenge() {
		return this.poseidon.squeeze();
	}
}

var poseidon_spec = {
	rF: 8,
	rP: 10,
	t: 17,
	rate: 16,
	constants: {
		start: [
			[
				[
					209, 15, 216, 74, 143, 216, 232, 205, 227, 203, 108, 41, 23,
					18, 124, 207, 81, 214, 198, 47, 40, 172, 236, 228, 249, 115,
					213, 204, 72, 226, 163, 4,
				],
				[
					7, 179, 223, 16, 252, 100, 0, 169, 103, 140, 187, 84, 124,
					236, 28, 80, 151, 141, 234, 182, 253, 173, 78, 65, 127, 67,
					137, 246, 227, 226, 210, 39,
				],
				[
					85, 188, 65, 151, 22, 85, 82, 248, 224, 92, 68, 106, 47,
					160, 34, 64, 143, 210, 203, 180, 2, 53, 159, 6, 28, 197,
					163, 186, 139, 7, 30, 33,
				],
				[
					143, 142, 180, 254, 60, 151, 218, 3, 138, 150, 94, 150, 55,
					78, 204, 81, 180, 193, 202, 192, 13, 121, 44, 153, 245, 12,
					170, 232, 224, 251, 21, 34,
				],
				[
					220, 110, 77, 125, 42, 55, 2, 116, 186, 166, 249, 27, 216,
					149, 5, 222, 160, 64, 233, 142, 2, 113, 180, 96, 172, 32,
					112, 5, 35, 200, 82, 15,
				],
				[
					94, 65, 36, 149, 210, 36, 172, 167, 143, 157, 33, 86, 53,
					148, 101, 36, 177, 11, 19, 116, 37, 226, 249, 91, 254, 105,
					174, 107, 243, 167, 127, 47,
				],
				[
					94, 130, 103, 62, 130, 253, 33, 40, 160, 51, 202, 190, 252,
					141, 45, 23, 167, 187, 25, 221, 85, 65, 207, 164, 42, 11,
					14, 12, 253, 6, 235, 43,
				],
				[
					164, 186, 75, 108, 41, 111, 227, 47, 139, 55, 146, 29, 208,
					96, 68, 29, 148, 118, 200, 111, 151, 24, 197, 63, 105, 118,
					184, 8, 211, 113, 29, 32,
				],
				[
					70, 222, 190, 163, 252, 74, 142, 49, 68, 138, 253, 220, 129,
					88, 184, 34, 207, 194, 90, 30, 148, 44, 228, 208, 145, 92,
					0, 179, 61, 193, 154, 11,
				],
				[
					39, 175, 93, 140, 137, 38, 54, 149, 146, 213, 181, 102, 25,
					162, 240, 237, 144, 224, 167, 70, 248, 32, 146, 135, 125,
					233, 31, 188, 160, 146, 125, 10,
				],
				[
					58, 79, 124, 7, 46, 159, 37, 237, 164, 96, 129, 173, 101,
					29, 78, 195, 209, 114, 25, 161, 114, 184, 229, 170, 212,
					102, 177, 83, 105, 144, 8, 6,
				],
				[
					214, 60, 247, 241, 92, 200, 185, 203, 137, 15, 138, 136, 54,
					12, 241, 165, 199, 132, 195, 249, 116, 158, 9, 192, 129, 1,
					167, 5, 187, 6, 68, 41,
				],
				[
					251, 124, 159, 167, 94, 25, 76, 244, 138, 24, 164, 202, 23,
					199, 199, 45, 113, 58, 143, 113, 101, 99, 97, 237, 84, 50,
					249, 218, 108, 136, 224, 0,
				],
				[
					225, 87, 209, 206, 196, 3, 210, 145, 88, 253, 45, 90, 12,
					153, 166, 165, 234, 247, 229, 179, 128, 120, 195, 114, 205,
					235, 11, 8, 169, 11, 106, 3,
				],
				[
					248, 199, 154, 55, 175, 144, 76, 176, 28, 125, 109, 140,
					165, 8, 68, 71, 238, 118, 208, 22, 76, 225, 34, 53, 85, 174,
					132, 9, 110, 122, 242, 35,
				],
				[
					82, 103, 72, 165, 24, 184, 171, 16, 76, 176, 74, 17, 88, 6,
					120, 166, 76, 180, 62, 53, 214, 109, 214, 168, 226, 161, 44,
					31, 143, 62, 3, 45,
				],
				[
					237, 232, 251, 30, 240, 176, 3, 206, 33, 115, 32, 86, 70,
					144, 177, 192, 104, 195, 103, 200, 101, 159, 255, 50, 49,
					88, 108, 54, 176, 77, 28, 38,
				],
			],
			[
				[
					124, 173, 103, 52, 112, 74, 31, 122, 157, 231, 36, 9, 2,
					127, 26, 74, 186, 230, 240, 156, 206, 233, 223, 64, 175, 6,
					141, 232, 205, 99, 83, 9,
				],
				[
					110, 172, 81, 110, 232, 58, 171, 16, 16, 200, 134, 251, 58,
					237, 39, 98, 41, 10, 59, 130, 50, 168, 101, 237, 70, 233,
					10, 214, 90, 74, 100, 14,
				],
				[
					226, 228, 126, 240, 251, 24, 214, 147, 240, 99, 182, 209,
					109, 223, 163, 211, 142, 227, 152, 230, 249, 218, 123, 173,
					13, 111, 236, 48, 103, 48, 40, 45,
				],
				[
					56, 253, 51, 28, 175, 32, 131, 74, 1, 154, 172, 115, 136,
					66, 17, 176, 199, 236, 54, 211, 16, 5, 223, 198, 81, 78,
					217, 242, 131, 163, 242, 16,
				],
				[
					152, 135, 113, 122, 162, 240, 191, 13, 22, 41, 200, 5, 33,
					138, 110, 71, 38, 128, 207, 53, 246, 76, 22, 190, 4, 81,
					205, 79, 248, 164, 92, 27,
				],
				[
					27, 186, 203, 216, 161, 69, 38, 23, 12, 174, 62, 62, 138,
					235, 247, 173, 103, 196, 51, 198, 163, 97, 94, 177, 157,
					102, 98, 223, 40, 143, 73, 44,
				],
				[
					191, 65, 172, 1, 28, 33, 203, 250, 222, 77, 24, 245, 140,
					237, 116, 26, 121, 191, 3, 215, 192, 171, 252, 155, 79, 43,
					254, 5, 86, 44, 144, 17,
				],
				[
					80, 158, 169, 138, 167, 188, 210, 137, 142, 23, 35, 53, 211,
					56, 132, 187, 213, 0, 89, 60, 213, 162, 47, 96, 137, 165,
					127, 202, 193, 25, 41, 11,
				],
				[
					17, 195, 52, 1, 92, 24, 138, 235, 250, 217, 226, 174, 60,
					56, 228, 121, 231, 245, 70, 143, 161, 150, 148, 242, 211,
					143, 91, 45, 207, 201, 236, 42,
				],
				[
					146, 231, 204, 240, 91, 64, 199, 145, 72, 235, 53, 188, 240,
					115, 14, 70, 20, 179, 185, 88, 201, 179, 43, 193, 48, 150,
					66, 94, 25, 158, 215, 34,
				],
				[
					198, 194, 11, 56, 205, 196, 231, 218, 96, 193, 226, 208,
					223, 119, 35, 138, 91, 44, 214, 82, 117, 211, 226, 222, 215,
					208, 17, 196, 186, 236, 7, 29,
				],
				[
					193, 134, 119, 167, 229, 166, 157, 137, 230, 74, 237, 121,
					134, 47, 199, 132, 10, 58, 235, 214, 73, 33, 165, 211, 155,
					222, 102, 152, 247, 35, 209, 1,
				],
				[
					124, 29, 247, 32, 208, 85, 250, 141, 254, 187, 7, 39, 126,
					98, 125, 104, 191, 0, 32, 57, 2, 53, 14, 22, 125, 127, 203,
					69, 146, 141, 205, 39,
				],
				[
					13, 241, 109, 37, 119, 37, 24, 198, 186, 160, 202, 139, 136,
					18, 200, 78, 167, 130, 30, 117, 152, 212, 2, 7, 77, 230,
					198, 158, 230, 213, 91, 23,
				],
				[
					237, 209, 200, 96, 75, 115, 32, 54, 147, 122, 156, 146, 84,
					176, 136, 199, 28, 11, 243, 159, 139, 194, 182, 76, 112,
					212, 162, 82, 71, 213, 20, 18,
				],
				[
					117, 4, 232, 65, 126, 153, 151, 89, 199, 29, 231, 59, 37,
					61, 89, 111, 135, 123, 90, 106, 43, 104, 165, 49, 52, 183,
					244, 34, 8, 217, 44, 17,
				],
				[
					159, 196, 153, 51, 63, 89, 24, 74, 102, 19, 140, 242, 157,
					109, 121, 94, 198, 197, 226, 106, 184, 242, 169, 190, 227,
					236, 224, 214, 162, 99, 231, 20,
				],
			],
			[
				[
					58, 185, 38, 122, 115, 17, 55, 104, 175, 125, 1, 244, 141,
					205, 137, 255, 12, 138, 139, 247, 146, 170, 48, 172, 186,
					134, 79, 64, 92, 206, 129, 36,
				],
				[
					216, 76, 112, 74, 246, 81, 231, 95, 249, 137, 3, 21, 28, 63,
					8, 225, 57, 233, 178, 224, 213, 127, 27, 134, 64, 159, 135,
					103, 138, 131, 93, 24,
				],
				[
					23, 92, 105, 180, 193, 170, 149, 65, 51, 188, 208, 241, 241,
					68, 251, 105, 54, 156, 102, 176, 123, 44, 59, 238, 162, 85,
					58, 143, 105, 218, 144, 47,
				],
				[
					205, 180, 250, 42, 192, 232, 212, 98, 248, 41, 188, 145,
					116, 101, 19, 143, 182, 90, 104, 113, 211, 49, 191, 245, 22,
					177, 42, 91, 32, 11, 199, 8,
				],
				[
					53, 70, 175, 231, 115, 43, 196, 67, 237, 37, 218, 29, 192,
					53, 4, 166, 144, 61, 162, 36, 37, 137, 217, 69, 191, 84,
					191, 41, 123, 29, 178, 5,
				],
				[
					140, 86, 247, 227, 204, 133, 137, 157, 218, 194, 209, 143,
					11, 168, 120, 108, 254, 167, 121, 89, 176, 207, 156, 124,
					43, 99, 111, 226, 87, 153, 219, 12,
				],
				[
					117, 113, 84, 184, 30, 229, 174, 250, 154, 124, 74, 44, 104,
					235, 193, 65, 59, 182, 190, 90, 91, 201, 230, 46, 249, 249,
					49, 21, 86, 30, 83, 15,
				],
				[
					170, 139, 15, 139, 118, 50, 17, 198, 117, 249, 157, 1, 202,
					252, 71, 102, 81, 238, 237, 30, 212, 121, 25, 190, 48, 82,
					84, 137, 159, 142, 77, 38,
				],
				[
					103, 2, 185, 33, 13, 224, 157, 7, 31, 248, 183, 237, 69, 37,
					126, 186, 0, 198, 129, 62, 19, 227, 252, 200, 97, 145, 115,
					246, 120, 179, 92, 10,
				],
				[
					49, 101, 207, 64, 116, 187, 59, 155, 31, 237, 44, 212, 148,
					80, 5, 90, 165, 0, 225, 63, 192, 250, 245, 63, 182, 234, 39,
					149, 99, 31, 154, 40,
				],
				[
					183, 81, 113, 204, 47, 73, 101, 183, 129, 144, 72, 10, 137,
					178, 18, 68, 105, 69, 139, 137, 39, 33, 49, 203, 146, 128,
					133, 124, 211, 246, 51, 27,
				],
				[
					34, 131, 162, 140, 129, 92, 111, 99, 68, 179, 29, 47, 235,
					104, 103, 137, 60, 207, 55, 58, 220, 153, 214, 98, 79, 206,
					250, 202, 78, 61, 194, 30,
				],
				[
					41, 126, 232, 86, 241, 141, 227, 38, 39, 213, 59, 3, 153,
					147, 30, 200, 194, 0, 237, 125, 255, 54, 89, 155, 39, 51,
					82, 11, 195, 24, 156, 32,
				],
				[
					195, 8, 228, 41, 231, 118, 162, 99, 211, 117, 59, 105, 129,
					211, 234, 117, 94, 231, 111, 160, 231, 152, 236, 117, 51,
					247, 202, 60, 242, 64, 213, 16,
				],
				[
					87, 254, 166, 194, 235, 204, 90, 179, 13, 49, 180, 68, 13,
					202, 121, 40, 21, 81, 52, 31, 112, 180, 192, 104, 80, 163,
					77, 104, 134, 80, 190, 23,
				],
				[
					68, 71, 99, 71, 95, 213, 35, 182, 129, 234, 241, 62, 28,
					119, 64, 46, 51, 130, 242, 68, 134, 146, 21, 219, 125, 74,
					79, 245, 81, 222, 45, 10,
				],
				[
					125, 108, 182, 161, 8, 90, 44, 175, 95, 15, 219, 156, 37,
					197, 227, 83, 122, 30, 186, 117, 110, 75, 196, 78, 145, 123,
					86, 217, 250, 79, 59, 35,
				],
			],
			[
				[
					240, 80, 136, 32, 223, 116, 161, 39, 19, 206, 231, 143, 239,
					245, 31, 120, 219, 196, 221, 72, 52, 27, 247, 51, 197, 83,
					125, 132, 83, 162, 240, 39,
				],
				[
					73, 220, 182, 184, 127, 140, 235, 195, 219, 236, 91, 237,
					112, 242, 244, 171, 213, 245, 154, 218, 64, 37, 83, 233, 17,
					214, 114, 19, 106, 128, 17, 22,
				],
				[
					90, 25, 229, 214, 225, 89, 242, 206, 52, 183, 41, 243, 148,
					229, 142, 154, 130, 212, 245, 157, 76, 93, 97, 75, 107, 2,
					86, 194, 150, 137, 158, 42,
				],
				[
					167, 70, 187, 207, 40, 199, 124, 201, 61, 172, 171, 2, 180,
					207, 199, 191, 80, 46, 146, 142, 94, 55, 86, 240, 33, 245,
					187, 205, 15, 87, 214, 40,
				],
				[
					5, 106, 137, 210, 124, 122, 11, 16, 26, 219, 227, 111, 103,
					102, 72, 139, 105, 51, 222, 110, 34, 33, 249, 97, 75, 193,
					86, 96, 198, 0, 42, 24,
				],
				[
					36, 88, 195, 165, 46, 58, 67, 114, 98, 243, 214, 148, 1,
					237, 3, 123, 27, 234, 105, 176, 197, 149, 20, 159, 142, 141,
					19, 244, 183, 117, 12, 15,
				],
				[
					74, 19, 178, 255, 162, 253, 51, 160, 21, 187, 88, 115, 15,
					216, 78, 112, 222, 144, 88, 139, 48, 50, 17, 40, 147, 169,
					40, 248, 245, 58, 183, 39,
				],
				[
					235, 68, 10, 45, 68, 136, 175, 71, 197, 199, 42, 22, 199,
					165, 235, 77, 68, 249, 190, 192, 227, 245, 60, 143, 241, 97,
					44, 55, 23, 188, 63, 36,
				],
				[
					138, 168, 39, 178, 214, 186, 223, 67, 113, 98, 23, 219, 232,
					186, 29, 253, 104, 8, 112, 177, 101, 37, 241, 191, 100, 166,
					193, 152, 21, 112, 197, 16,
				],
				[
					126, 115, 19, 4, 156, 237, 0, 178, 78, 61, 70, 205, 248, 24,
					102, 244, 140, 164, 220, 150, 14, 123, 133, 168, 24, 69,
					113, 29, 120, 101, 26, 41,
				],
				[
					171, 212, 116, 88, 243, 152, 141, 192, 181, 238, 30, 142,
					113, 133, 227, 49, 102, 197, 56, 206, 81, 11, 186, 30, 172,
					209, 142, 48, 43, 47, 105, 3,
				],
				[
					137, 255, 239, 172, 239, 233, 50, 157, 253, 9, 201, 10, 77,
					164, 137, 222, 174, 52, 17, 16, 64, 255, 39, 141, 70, 16,
					115, 151, 77, 243, 196, 18,
				],
				[
					219, 8, 127, 51, 248, 142, 121, 131, 25, 86, 19, 87, 42,
					130, 205, 80, 14, 106, 26, 84, 136, 198, 124, 33, 188, 159,
					121, 225, 185, 13, 47, 8,
				],
				[
					152, 242, 33, 166, 138, 42, 16, 229, 80, 32, 9, 8, 247, 47,
					227, 195, 79, 154, 181, 253, 248, 125, 169, 160, 61, 14, 97,
					137, 191, 225, 159, 16,
				],
				[
					68, 197, 81, 182, 184, 235, 43, 186, 149, 175, 207, 80, 120,
					10, 245, 124, 116, 157, 103, 141, 220, 22, 159, 25, 85, 62,
					115, 42, 49, 56, 164, 22,
				],
				[
					162, 128, 240, 114, 125, 59, 23, 47, 243, 93, 214, 205, 243,
					136, 192, 13, 27, 88, 14, 88, 41, 114, 103, 81, 98, 35, 168,
					146, 117, 223, 251, 40,
				],
				[
					176, 105, 244, 145, 98, 250, 15, 209, 142, 55, 2, 112, 64,
					180, 42, 105, 40, 34, 166, 161, 195, 208, 172, 145, 217,
					228, 223, 13, 196, 130, 212, 36,
				],
			],
			[
				[
					185, 126, 253, 85, 128, 37, 92, 188, 75, 109, 153, 22, 55,
					209, 15, 154, 86, 122, 4, 132, 157, 56, 113, 3, 181, 137,
					244, 213, 51, 66, 152, 32,
				],
				[
					240, 119, 204, 46, 219, 202, 127, 254, 126, 154, 93, 17, 12,
					126, 160, 94, 82, 120, 15, 174, 152, 76, 213, 125, 139, 95,
					64, 68, 25, 125, 137, 8,
				],
				[
					68, 74, 162, 159, 26, 14, 238, 30, 95, 58, 157, 216, 8, 190,
					86, 150, 96, 241, 143, 181, 104, 207, 161, 43, 153, 108, 99,
					244, 145, 50, 136, 20,
				],
				[
					19, 112, 92, 159, 24, 180, 96, 12, 64, 60, 209, 79, 86, 26,
					19, 140, 69, 117, 78, 103, 200, 70, 44, 23, 221, 87, 4, 58,
					148, 210, 2, 31,
				],
				[
					107, 246, 12, 115, 242, 11, 110, 60, 18, 35, 136, 34, 159,
					75, 187, 230, 151, 130, 214, 23, 155, 78, 1, 126, 180, 247,
					56, 67, 243, 50, 72, 32,
				],
				[
					78, 246, 73, 23, 205, 194, 52, 135, 78, 138, 130, 14, 75,
					94, 128, 29, 255, 86, 72, 205, 193, 43, 40, 32, 255, 52,
					232, 164, 180, 62, 18, 21,
				],
				[
					30, 19, 104, 144, 62, 6, 176, 226, 77, 152, 142, 169, 113,
					149, 59, 81, 142, 62, 246, 8, 42, 102, 179, 115, 191, 159,
					197, 131, 113, 79, 4, 31,
				],
				[
					232, 179, 66, 144, 45, 28, 17, 217, 193, 249, 248, 59, 49,
					186, 216, 222, 15, 34, 121, 114, 54, 110, 206, 150, 174, 52,
					181, 176, 173, 104, 121, 7,
				],
				[
					248, 106, 158, 211, 110, 231, 194, 226, 105, 147, 121, 199,
					65, 189, 253, 45, 102, 159, 208, 146, 25, 182, 48, 94, 142,
					215, 32, 8, 176, 8, 183, 39,
				],
				[
					194, 106, 103, 106, 98, 130, 12, 246, 115, 213, 114, 147,
					254, 183, 70, 204, 244, 139, 87, 23, 233, 48, 154, 210, 38,
					155, 127, 164, 21, 19, 98, 26,
				],
				[
					30, 64, 9, 254, 75, 239, 15, 191, 85, 50, 196, 137, 238, 79,
					36, 20, 95, 118, 85, 92, 158, 202, 110, 128, 244, 140, 58,
					142, 93, 78, 92, 46,
				],
				[
					88, 98, 151, 97, 4, 205, 223, 126, 106, 148, 166, 209, 181,
					119, 87, 188, 236, 26, 89, 43, 97, 114, 87, 201, 168, 62,
					143, 221, 204, 169, 16, 33,
				],
				[
					132, 16, 118, 181, 209, 111, 185, 213, 22, 44, 159, 73, 170,
					151, 18, 191, 87, 193, 125, 155, 71, 203, 6, 61, 101, 73,
					244, 173, 0, 149, 219, 47,
				],
				[
					254, 121, 120, 213, 50, 17, 102, 5, 246, 49, 21, 56, 172,
					42, 29, 228, 62, 2, 184, 207, 221, 117, 30, 79, 109, 79, 97,
					76, 103, 6, 125, 35,
				],
				[
					184, 86, 55, 218, 48, 33, 25, 60, 206, 52, 15, 98, 159, 51,
					57, 75, 153, 157, 55, 209, 246, 71, 85, 54, 10, 230, 55,
					156, 176, 248, 45, 28,
				],
				[
					8, 162, 247, 59, 149, 41, 249, 208, 234, 201, 107, 147, 12,
					180, 124, 13, 167, 18, 184, 200, 57, 14, 253, 154, 244, 76,
					255, 157, 155, 137, 51, 43,
				],
				[
					206, 202, 204, 146, 216, 192, 251, 206, 32, 242, 31, 70,
					201, 27, 5, 189, 188, 151, 81, 180, 52, 139, 246, 43, 30,
					27, 219, 151, 123, 192, 214, 19,
				],
			],
		],
		end: [
			[
				[
					231, 106, 43, 214, 33, 110, 78, 217, 73, 240, 157, 69, 104,
					60, 89, 73, 35, 238, 203, 144, 144, 81, 172, 182, 197, 235,
					127, 168, 212, 146, 59, 11,
				],
				[
					80, 33, 112, 152, 80, 194, 191, 42, 74, 173, 74, 35, 59, 28,
					90, 167, 226, 42, 220, 129, 32, 225, 77, 217, 176, 148, 196,
					154, 116, 76, 171, 18,
				],
				[
					77, 37, 108, 245, 69, 45, 99, 5, 190, 21, 252, 195, 55, 101,
					178, 200, 99, 152, 68, 60, 9, 12, 195, 224, 179, 208, 229,
					109, 3, 172, 107, 3,
				],
				[
					107, 101, 115, 25, 134, 216, 30, 119, 73, 92, 216, 190, 58,
					205, 239, 68, 45, 13, 137, 238, 139, 115, 96, 253, 122, 48,
					20, 172, 119, 134, 138, 18,
				],
				[
					227, 244, 58, 127, 229, 14, 249, 82, 218, 88, 10, 255, 8,
					154, 13, 17, 183, 55, 50, 173, 85, 77, 230, 201, 9, 129,
					206, 165, 165, 174, 67, 37,
				],
				[
					21, 111, 63, 99, 122, 148, 92, 9, 120, 225, 253, 250, 113,
					72, 50, 203, 19, 249, 73, 245, 209, 224, 54, 200, 194, 165,
					156, 165, 235, 9, 33, 13,
				],
				[
					24, 229, 200, 67, 92, 189, 11, 225, 125, 10, 109, 131, 2,
					206, 246, 71, 49, 140, 77, 64, 241, 228, 75, 218, 110, 134,
					3, 175, 110, 117, 0, 2,
				],
				[
					77, 8, 194, 77, 35, 97, 31, 242, 129, 168, 237, 25, 104,
					108, 79, 190, 104, 177, 143, 16, 3, 205, 208, 209, 35, 255,
					54, 26, 164, 212, 132, 4,
				],
				[
					186, 144, 199, 203, 174, 194, 248, 180, 186, 221, 219, 234,
					116, 243, 114, 81, 206, 118, 46, 66, 180, 31, 73, 107, 106,
					18, 117, 184, 210, 163, 110, 22,
				],
				[
					81, 160, 173, 251, 131, 254, 249, 245, 247, 109, 161, 227,
					234, 18, 254, 53, 198, 177, 207, 185, 57, 220, 4, 233, 77,
					62, 90, 32, 10, 223, 17, 15,
				],
				[
					243, 123, 250, 82, 41, 72, 71, 162, 151, 151, 174, 31, 91,
					128, 122, 175, 28, 72, 144, 70, 32, 165, 153, 203, 74, 75,
					69, 254, 231, 239, 114, 3,
				],
				[
					19, 21, 73, 76, 5, 128, 136, 239, 55, 222, 181, 182, 202,
					39, 130, 78, 102, 252, 206, 183, 75, 58, 55, 231, 160, 115,
					104, 128, 164, 77, 133, 25,
				],
				[
					96, 141, 77, 6, 16, 199, 115, 206, 93, 19, 3, 118, 103, 2,
					94, 112, 56, 95, 187, 190, 232, 8, 78, 255, 245, 80, 58,
					238, 126, 255, 154, 26,
				],
				[
					16, 21, 124, 154, 121, 173, 207, 174, 40, 87, 33, 108, 66,
					79, 133, 80, 152, 210, 26, 8, 180, 239, 222, 118, 64, 40,
					179, 203, 103, 180, 131, 21,
				],
				[
					217, 239, 47, 106, 109, 146, 162, 198, 233, 201, 130, 22,
					10, 24, 71, 84, 114, 248, 12, 184, 207, 38, 82, 229, 248,
					40, 52, 173, 174, 105, 79, 26,
				],
				[
					105, 41, 224, 185, 114, 6, 243, 11, 139, 29, 135, 66, 141,
					159, 136, 171, 20, 86, 105, 24, 15, 129, 139, 5, 8, 120,
					172, 213, 155, 47, 218, 16,
				],
				[
					75, 198, 243, 25, 125, 223, 56, 101, 35, 232, 115, 136, 7,
					238, 20, 211, 10, 107, 205, 126, 40, 63, 206, 48, 144, 251,
					249, 244, 238, 220, 215, 19,
				],
			],
			[
				[
					145, 50, 28, 213, 81, 152, 242, 201, 11, 48, 253, 245, 29,
					24, 231, 248, 211, 31, 148, 248, 52, 233, 190, 186, 48, 241,
					109, 152, 171, 229, 173, 30,
				],
				[
					80, 0, 157, 171, 169, 84, 111, 86, 249, 50, 111, 102, 34,
					245, 16, 147, 9, 13, 163, 166, 56, 21, 147, 41, 210, 30, 33,
					129, 212, 104, 216, 4,
				],
				[
					111, 51, 203, 78, 15, 76, 251, 11, 161, 19, 63, 118, 192,
					125, 16, 22, 145, 97, 48, 60, 50, 187, 233, 178, 60, 101,
					22, 106, 171, 32, 8, 11,
				],
				[
					136, 125, 230, 21, 37, 220, 17, 79, 236, 188, 44, 194, 172,
					43, 199, 120, 121, 212, 18, 183, 211, 17, 168, 235, 195,
					221, 114, 74, 17, 141, 218, 46,
				],
				[
					249, 81, 169, 7, 15, 249, 108, 197, 114, 243, 52, 111, 23,
					16, 76, 168, 81, 67, 15, 246, 38, 125, 159, 26, 32, 33, 42,
					228, 230, 104, 141, 24,
				],
				[
					192, 89, 216, 27, 83, 197, 27, 69, 249, 196, 181, 241, 80,
					194, 38, 0, 170, 35, 226, 100, 122, 5, 96, 89, 114, 6, 171,
					195, 137, 171, 204, 0,
				],
				[
					5, 55, 198, 132, 109, 171, 52, 34, 54, 121, 96, 144, 27, 5,
					31, 159, 86, 222, 38, 4, 56, 228, 192, 185, 66, 92, 109,
					199, 240, 70, 78, 6,
				],
				[
					41, 84, 71, 30, 53, 36, 212, 144, 102, 192, 148, 88, 53,
					122, 199, 142, 27, 212, 227, 178, 84, 90, 115, 123, 182,
					237, 241, 138, 34, 66, 121, 47,
				],
				[
					146, 182, 215, 112, 92, 62, 170, 179, 44, 1, 228, 9, 196,
					240, 139, 230, 190, 171, 43, 28, 141, 251, 149, 147, 11, 82,
					24, 3, 158, 6, 137, 10,
				],
				[
					199, 126, 146, 41, 98, 245, 171, 255, 229, 107, 35, 190, 1,
					139, 48, 154, 71, 211, 135, 103, 83, 122, 247, 1, 79, 107,
					91, 27, 224, 73, 202, 0,
				],
				[
					226, 100, 243, 15, 53, 7, 126, 84, 106, 249, 235, 242, 98,
					87, 223, 13, 109, 58, 133, 3, 92, 141, 131, 198, 211, 249,
					220, 237, 180, 48, 94, 40,
				],
				[
					37, 17, 194, 156, 94, 254, 242, 217, 238, 217, 170, 186, 95,
					39, 6, 65, 191, 82, 110, 65, 61, 182, 200, 107, 5, 121, 253,
					83, 36, 253, 209, 29,
				],
				[
					226, 185, 203, 228, 20, 130, 209, 87, 104, 38, 221, 179,
					237, 236, 193, 22, 179, 148, 203, 91, 243, 126, 201, 129,
					142, 255, 118, 201, 31, 210, 191, 46,
				],
				[
					217, 188, 57, 43, 14, 192, 226, 66, 216, 77, 227, 249, 172,
					52, 228, 201, 7, 186, 220, 226, 52, 218, 118, 142, 2, 20,
					78, 252, 12, 100, 233, 39,
				],
				[
					196, 239, 17, 213, 24, 242, 222, 10, 132, 106, 2, 240, 247,
					130, 84, 234, 43, 36, 40, 93, 95, 163, 19, 132, 94, 187, 15,
					34, 62, 255, 240, 38,
				],
				[
					151, 78, 252, 31, 157, 95, 183, 201, 242, 88, 73, 188, 119,
					151, 63, 158, 113, 218, 156, 115, 171, 233, 35, 246, 247,
					235, 151, 145, 87, 20, 238, 17,
				],
				[
					149, 209, 145, 90, 201, 61, 86, 73, 82, 37, 93, 243, 165,
					202, 218, 33, 239, 46, 20, 81, 9, 90, 161, 246, 181, 233,
					242, 138, 1, 71, 242, 24,
				],
			],
			[
				[
					64, 217, 211, 24, 159, 68, 186, 24, 151, 29, 4, 225, 210,
					117, 156, 95, 177, 119, 140, 173, 99, 56, 32, 19, 48, 240,
					86, 50, 110, 62, 248, 21,
				],
				[
					21, 162, 141, 15, 243, 133, 105, 210, 82, 227, 121, 103,
					221, 12, 235, 170, 181, 160, 194, 240, 221, 252, 92, 43,
					236, 17, 37, 242, 233, 98, 65, 15,
				],
				[
					137, 176, 124, 74, 17, 177, 182, 220, 30, 107, 190, 107,
					249, 201, 158, 93, 46, 166, 205, 114, 35, 37, 72, 221, 23,
					246, 26, 139, 239, 162, 141, 5,
				],
				[
					65, 49, 152, 223, 176, 172, 21, 173, 2, 129, 179, 142, 230,
					25, 120, 213, 250, 58, 81, 90, 168, 136, 137, 197, 182, 116,
					241, 96, 119, 54, 43, 27,
				],
				[
					255, 70, 100, 105, 247, 58, 25, 16, 168, 204, 230, 253, 169,
					208, 254, 21, 52, 75, 237, 223, 102, 44, 55, 132, 52, 120,
					121, 76, 48, 101, 128, 3,
				],
				[
					138, 7, 143, 13, 104, 36, 164, 180, 201, 12, 178, 98, 135,
					104, 184, 171, 207, 49, 133, 186, 221, 60, 112, 203, 10, 36,
					29, 88, 120, 142, 114, 47,
				],
				[
					14, 188, 20, 251, 122, 44, 129, 50, 136, 64, 46, 111, 67,
					95, 60, 209, 96, 253, 198, 137, 42, 113, 121, 184, 124, 65,
					7, 134, 82, 28, 94, 40,
				],
				[
					244, 132, 159, 6, 44, 185, 62, 92, 249, 250, 13, 33, 120,
					107, 161, 103, 49, 38, 61, 10, 199, 204, 181, 146, 16, 148,
					183, 19, 239, 105, 64, 41,
				],
				[
					193, 115, 26, 123, 56, 67, 202, 39, 149, 26, 37, 239, 80,
					209, 44, 105, 96, 230, 215, 119, 33, 243, 219, 54, 230, 127,
					35, 35, 48, 236, 155, 29,
				],
				[
					178, 155, 17, 86, 146, 108, 160, 123, 33, 169, 228, 49, 177,
					215, 184, 2, 134, 40, 219, 161, 5, 122, 43, 232, 39, 164,
					212, 251, 152, 146, 36, 38,
				],
				[
					160, 142, 30, 25, 110, 67, 222, 50, 222, 178, 246, 243, 60,
					41, 163, 171, 99, 235, 97, 53, 120, 157, 237, 52, 242, 71,
					114, 81, 40, 153, 100, 38,
				],
				[
					198, 64, 167, 95, 225, 99, 32, 209, 194, 175, 227, 186, 107,
					179, 134, 102, 81, 3, 214, 36, 76, 140, 91, 231, 152, 145,
					31, 170, 248, 222, 142, 44,
				],
				[
					77, 227, 114, 114, 111, 116, 76, 4, 143, 32, 99, 4, 0, 223,
					235, 10, 3, 159, 154, 137, 121, 221, 126, 255, 44, 92, 21,
					19, 224, 38, 52, 3,
				],
				[
					157, 221, 5, 29, 214, 125, 234, 9, 99, 16, 173, 124, 25,
					223, 126, 229, 225, 52, 163, 105, 195, 136, 129, 164, 95,
					53, 104, 224, 90, 139, 110, 29,
				],
				[
					114, 84, 107, 220, 252, 21, 242, 199, 92, 84, 159, 64, 184,
					43, 225, 121, 208, 234, 85, 243, 35, 190, 99, 126, 242, 41,
					33, 215, 149, 59, 185, 36,
				],
				[
					119, 141, 67, 216, 229, 147, 86, 233, 123, 119, 126, 106,
					172, 213, 99, 16, 97, 125, 141, 182, 113, 43, 151, 152, 108,
					35, 27, 18, 152, 202, 112, 32,
				],
				[
					228, 212, 248, 74, 156, 73, 77, 103, 225, 190, 80, 25, 110,
					246, 111, 9, 153, 199, 153, 43, 165, 18, 145, 108, 36, 103,
					85, 30, 159, 107, 217, 19,
				],
			],
		],
		partial: [
			[
				54, 230, 113, 217, 208, 130, 31, 12, 193, 178, 23, 218, 212,
				192, 156, 231, 156, 81, 190, 142, 121, 87, 247, 228, 255, 225,
				34, 115, 127, 121, 144, 12,
			],
			[
				123, 194, 203, 6, 209, 113, 7, 209, 174, 155, 36, 109, 98, 93,
				0, 159, 0, 113, 124, 155, 94, 250, 234, 56, 70, 80, 127, 31, 83,
				116, 48, 35,
			],
			[
				180, 225, 156, 56, 236, 216, 188, 165, 84, 195, 37, 251, 96,
				157, 220, 207, 195, 154, 70, 208, 37, 140, 246, 179, 47, 180,
				254, 81, 219, 29, 52, 37,
			],
			[
				33, 205, 203, 121, 75, 5, 48, 208, 114, 162, 229, 189, 202, 240,
				244, 177, 68, 174, 152, 171, 4, 42, 113, 22, 146, 163, 30, 248,
				127, 135, 202, 38,
			],
			[
				84, 4, 129, 91, 203, 96, 66, 222, 234, 87, 124, 114, 239, 250,
				173, 184, 254, 164, 93, 186, 191, 9, 182, 27, 95, 30, 15, 140,
				89, 193, 13, 25,
			],
			[
				3, 252, 156, 31, 128, 57, 128, 107, 59, 206, 12, 6, 166, 90, 48,
				145, 87, 105, 61, 186, 117, 26, 213, 49, 216, 190, 101, 92, 242,
				89, 251, 25,
			],
			[
				68, 27, 155, 191, 65, 8, 169, 160, 27, 116, 243, 79, 47, 128,
				52, 36, 178, 212, 148, 15, 55, 62, 238, 234, 198, 192, 149, 117,
				1, 101, 226, 9,
			],
			[
				231, 233, 182, 166, 146, 9, 104, 79, 188, 39, 225, 165, 19, 148,
				212, 215, 82, 18, 251, 10, 76, 39, 206, 252, 40, 57, 239, 51,
				237, 207, 92, 2,
			],
			[
				111, 204, 15, 199, 160, 73, 247, 191, 13, 185, 10, 59, 25, 223,
				180, 86, 12, 52, 194, 76, 93, 154, 237, 146, 205, 6, 171, 182,
				231, 103, 27, 13,
			],
			[
				80, 56, 131, 39, 213, 182, 29, 170, 197, 91, 162, 69, 75, 136,
				28, 72, 29, 94, 142, 136, 9, 73, 59, 170, 153, 7, 84, 177, 117,
				9, 247, 18,
			],
		],
	},
	mdsMatrices: {
		mds: [
			[
				[
					91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228, 101,
					147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185, 133, 145,
					82, 177, 17, 34, 22, 8,
				],
				[
					148, 155, 245, 18, 213, 66, 52, 6, 253, 149, 30, 99, 62, 7,
					110, 250, 157, 199, 250, 4, 45, 228, 62, 26, 59, 77, 47,
					226, 147, 171, 127, 5,
				],
				[
					84, 92, 70, 226, 64, 19, 10, 220, 103, 122, 171, 11, 227,
					38, 218, 19, 54, 45, 204, 199, 20, 203, 32, 67, 93, 86, 119,
					58, 118, 232, 11, 29,
				],
				[
					111, 133, 150, 243, 83, 74, 102, 163, 28, 51, 30, 254, 209,
					235, 88, 91, 10, 162, 177, 38, 186, 202, 150, 188, 253, 133,
					175, 152, 187, 65, 131, 24,
				],
				[
					208, 141, 223, 214, 116, 40, 45, 40, 38, 70, 17, 254, 129,
					144, 25, 102, 127, 159, 174, 104, 144, 87, 123, 156, 89,
					185, 156, 72, 171, 174, 151, 1,
				],
				[
					137, 168, 125, 99, 16, 158, 75, 115, 45, 0, 115, 225, 216,
					50, 28, 219, 155, 134, 141, 116, 91, 165, 135, 38, 102, 5,
					228, 249, 146, 125, 116, 45,
				],
				[
					56, 106, 10, 12, 230, 94, 200, 78, 181, 187, 209, 56, 254,
					56, 114, 62, 241, 182, 27, 245, 87, 191, 130, 59, 140, 201,
					36, 186, 187, 85, 171, 33,
				],
				[
					32, 131, 248, 5, 209, 17, 141, 252, 196, 36, 28, 225, 46,
					242, 160, 219, 202, 235, 72, 42, 60, 59, 185, 79, 255, 135,
					138, 33, 113, 12, 121, 0,
				],
				[
					186, 250, 134, 176, 101, 153, 237, 245, 179, 108, 79, 20,
					28, 251, 27, 181, 41, 148, 191, 44, 226, 183, 16, 94, 162,
					234, 208, 35, 46, 155, 73, 29,
				],
				[
					218, 171, 30, 172, 79, 13, 253, 147, 195, 220, 207, 153,
					127, 180, 12, 113, 248, 163, 192, 194, 86, 87, 183, 155,
					116, 248, 3, 62, 251, 225, 31, 24,
				],
				[
					132, 67, 56, 189, 234, 169, 13, 249, 170, 3, 103, 36, 45,
					175, 133, 236, 220, 14, 26, 155, 238, 160, 88, 109, 22, 122,
					152, 91, 173, 233, 154, 16,
				],
				[
					177, 210, 179, 16, 42, 153, 167, 81, 113, 46, 108, 152, 63,
					202, 189, 77, 215, 204, 144, 58, 184, 252, 151, 129, 20,
					250, 42, 63, 146, 23, 136, 15,
				],
				[
					21, 205, 63, 232, 120, 107, 160, 163, 143, 198, 88, 171, 58,
					127, 85, 74, 205, 132, 46, 9, 195, 76, 55, 113, 255, 250,
					188, 15, 133, 196, 191, 5,
				],
				[
					182, 81, 253, 171, 216, 222, 185, 71, 246, 55, 33, 195, 147,
					240, 14, 62, 190, 144, 26, 36, 106, 25, 83, 120, 102, 123,
					33, 193, 204, 114, 32, 45,
				],
				[
					208, 189, 211, 138, 74, 142, 238, 120, 252, 138, 154, 26,
					12, 237, 136, 29, 193, 9, 185, 194, 186, 135, 80, 239, 226,
					160, 220, 182, 141, 25, 20, 8,
				],
				[
					95, 195, 150, 105, 76, 26, 81, 173, 250, 142, 97, 51, 222,
					217, 223, 162, 14, 71, 45, 120, 68, 67, 123, 188, 109, 220,
					126, 215, 213, 140, 216, 31,
				],
				[
					123, 166, 111, 13, 143, 79, 117, 203, 246, 152, 96, 169, 34,
					175, 6, 189, 54, 53, 19, 112, 58, 125, 247, 97, 250, 120,
					249, 180, 37, 91, 143, 7,
				],
			],
			[
				[
					153, 29, 12, 139, 86, 241, 82, 44, 38, 78, 29, 158, 170,
					207, 250, 132, 244, 99, 190, 226, 47, 99, 228, 175, 87, 253,
					80, 70, 91, 151, 81, 8,
				],
				[
					208, 90, 104, 199, 92, 11, 83, 185, 91, 114, 209, 35, 186,
					120, 198, 131, 108, 80, 158, 148, 179, 201, 110, 89, 202,
					78, 17, 13, 196, 111, 185, 26,
				],
				[
					206, 63, 150, 192, 116, 143, 251, 247, 76, 218, 22, 187,
					200, 48, 234, 195, 26, 194, 222, 142, 190, 181, 38, 125,
					241, 175, 230, 127, 9, 153, 160, 41,
				],
				[
					14, 115, 239, 82, 25, 93, 140, 227, 119, 244, 66, 203, 59,
					152, 40, 106, 10, 10, 77, 160, 102, 129, 175, 141, 152, 184,
					125, 57, 175, 188, 146, 42,
				],
				[
					224, 178, 254, 218, 244, 63, 145, 223, 42, 92, 164, 48, 93,
					196, 110, 235, 237, 40, 57, 138, 146, 147, 45, 40, 152, 205,
					132, 213, 176, 171, 65, 7,
				],
				[
					236, 13, 93, 56, 8, 167, 240, 133, 147, 65, 115, 22, 247,
					65, 19, 151, 45, 209, 184, 35, 214, 178, 72, 93, 83, 177,
					77, 77, 247, 233, 199, 8,
				],
				[
					237, 11, 117, 216, 79, 253, 181, 119, 191, 145, 92, 133,
					170, 173, 168, 96, 45, 125, 235, 148, 243, 99, 150, 111,
					249, 37, 171, 38, 240, 34, 14, 14,
				],
				[
					145, 46, 97, 53, 94, 181, 54, 32, 116, 251, 63, 53, 7, 45,
					132, 96, 191, 216, 136, 107, 171, 38, 132, 209, 92, 119,
					131, 234, 120, 107, 20, 28,
				],
				[
					181, 134, 39, 229, 66, 117, 23, 214, 134, 61, 155, 236, 65,
					204, 168, 145, 132, 69, 153, 219, 253, 33, 26, 192, 46, 178,
					37, 130, 82, 84, 1, 33,
				],
				[
					149, 210, 14, 78, 16, 42, 227, 71, 155, 205, 238, 75, 38,
					171, 101, 156, 246, 32, 2, 159, 54, 63, 230, 191, 164, 23,
					12, 31, 98, 134, 99, 4,
				],
				[
					160, 213, 109, 231, 118, 141, 66, 46, 217, 74, 67, 128, 240,
					135, 113, 108, 105, 231, 97, 197, 59, 187, 216, 147, 6, 65,
					217, 88, 62, 88, 176, 22,
				],
				[
					247, 130, 227, 163, 66, 91, 36, 173, 159, 40, 80, 184, 94,
					102, 178, 22, 55, 250, 133, 102, 127, 109, 111, 54, 223,
					170, 118, 84, 226, 39, 230, 24,
				],
				[
					43, 128, 133, 211, 8, 214, 226, 12, 182, 69, 146, 254, 19,
					121, 10, 89, 34, 83, 100, 40, 173, 148, 64, 201, 175, 129,
					213, 170, 242, 146, 76, 16,
				],
				[
					46, 132, 222, 148, 33, 246, 170, 247, 154, 27, 73, 70, 155,
					7, 211, 204, 155, 163, 177, 0, 159, 119, 33, 114, 208, 60,
					102, 36, 132, 61, 135, 26,
				],
				[
					28, 131, 42, 197, 86, 141, 37, 179, 1, 193, 7, 93, 105, 84,
					112, 29, 230, 41, 56, 189, 145, 78, 174, 68, 186, 135, 202,
					180, 199, 129, 31, 30,
				],
				[
					143, 116, 186, 153, 138, 10, 173, 143, 253, 232, 226, 191,
					164, 155, 114, 132, 8, 238, 160, 63, 136, 106, 50, 151, 199,
					5, 126, 231, 185, 187, 33, 47,
				],
				[
					246, 203, 31, 230, 253, 149, 46, 79, 64, 224, 64, 90, 9,
					113, 83, 132, 42, 110, 81, 1, 9, 71, 17, 250, 111, 31, 11,
					183, 105, 11, 182, 9,
				],
			],
			[
				[
					246, 241, 212, 95, 177, 1, 5, 208, 184, 137, 89, 155, 28,
					132, 163, 160, 123, 115, 68, 102, 247, 210, 158, 196, 144,
					132, 231, 12, 166, 253, 243, 3,
				],
				[
					203, 230, 32, 245, 214, 106, 250, 53, 176, 121, 218, 64, 30,
					64, 171, 245, 44, 8, 84, 44, 48, 12, 181, 200, 125, 34, 255,
					216, 42, 194, 76, 35,
				],
				[
					68, 217, 134, 232, 86, 225, 184, 114, 124, 109, 26, 99, 156,
					47, 75, 126, 13, 104, 62, 5, 208, 237, 23, 226, 142, 73,
					209, 229, 211, 251, 231, 42,
				],
				[
					237, 182, 27, 216, 106, 135, 241, 118, 104, 39, 17, 120, 97,
					63, 14, 17, 153, 11, 27, 56, 102, 26, 191, 48, 2, 140, 246,
					133, 40, 55, 20, 15,
				],
				[
					9, 187, 24, 79, 161, 179, 156, 164, 81, 167, 130, 154, 105,
					116, 50, 226, 94, 12, 235, 16, 96, 44, 127, 234, 119, 110,
					84, 82, 11, 206, 88, 26,
				],
				[
					8, 230, 66, 164, 246, 46, 150, 70, 122, 209, 205, 25, 234,
					121, 204, 43, 115, 147, 254, 178, 194, 34, 244, 26, 93, 51,
					26, 83, 222, 9, 249, 36,
				],
				[
					48, 153, 11, 55, 112, 108, 74, 97, 29, 28, 145, 241, 157,
					219, 66, 8, 35, 8, 185, 249, 52, 139, 162, 128, 197, 90,
					155, 173, 177, 172, 154, 36,
				],
				[
					248, 60, 169, 46, 200, 128, 204, 182, 39, 33, 58, 188, 229,
					208, 159, 89, 231, 255, 249, 12, 76, 118, 143, 48, 18, 144,
					224, 192, 108, 168, 198, 43,
				],
				[
					127, 111, 165, 87, 146, 164, 230, 123, 235, 12, 231, 99, 13,
					125, 173, 31, 20, 216, 53, 189, 144, 142, 219, 195, 19, 230,
					84, 149, 99, 233, 244, 36,
				],
				[
					101, 242, 190, 159, 204, 177, 75, 29, 138, 253, 184, 46,
					190, 23, 131, 200, 243, 233, 206, 9, 184, 117, 194, 91, 73,
					211, 72, 172, 2, 88, 56, 44,
				],
				[
					97, 25, 76, 20, 13, 224, 198, 111, 24, 247, 112, 140, 173,
					138, 160, 122, 89, 121, 144, 28, 114, 37, 27, 12, 20, 102,
					41, 53, 230, 195, 87, 23,
				],
				[
					114, 110, 105, 247, 139, 98, 14, 225, 111, 22, 95, 173, 126,
					144, 150, 46, 46, 232, 146, 158, 57, 18, 23, 156, 167, 149,
					16, 34, 168, 73, 54, 27,
				],
				[
					137, 96, 97, 226, 21, 106, 73, 0, 255, 86, 146, 244, 11, 43,
					189, 71, 72, 172, 27, 79, 38, 41, 1, 126, 80, 251, 203, 220,
					139, 9, 22, 9,
				],
				[
					202, 110, 141, 251, 39, 203, 71, 246, 167, 137, 223, 178,
					74, 103, 171, 151, 144, 230, 21, 65, 120, 139, 22, 50, 17,
					208, 34, 238, 189, 118, 146, 46,
				],
				[
					110, 26, 246, 13, 104, 149, 200, 208, 86, 1, 129, 172, 226,
					97, 144, 237, 89, 175, 115, 142, 79, 248, 193, 250, 56, 16,
					195, 233, 71, 244, 140, 22,
				],
				[
					8, 225, 95, 153, 95, 164, 225, 246, 133, 112, 176, 52, 255,
					36, 26, 215, 160, 240, 181, 54, 37, 150, 45, 30, 225, 189,
					157, 126, 173, 134, 178, 12,
				],
				[
					3, 150, 22, 123, 115, 163, 226, 214, 182, 167, 40, 95, 9,
					95, 115, 53, 58, 77, 198, 38, 126, 186, 103, 188, 66, 42,
					199, 79, 181, 197, 97, 30,
				],
			],
			[
				[
					36, 207, 205, 101, 188, 2, 238, 207, 250, 202, 229, 22, 73,
					122, 236, 225, 2, 169, 235, 105, 82, 156, 34, 178, 70, 115,
					132, 95, 69, 33, 247, 45,
				],
				[
					67, 60, 192, 104, 0, 24, 12, 218, 139, 32, 166, 174, 71,
					156, 248, 218, 107, 66, 255, 58, 244, 126, 85, 77, 58, 139,
					133, 190, 255, 255, 45, 9,
				],
				[
					64, 232, 88, 21, 111, 72, 131, 28, 97, 81, 0, 179, 67, 231,
					1, 252, 78, 96, 164, 21, 242, 87, 47, 9, 17, 25, 40, 230,
					29, 36, 171, 4,
				],
				[
					128, 88, 2, 196, 83, 111, 89, 215, 89, 232, 161, 160, 239,
					142, 206, 130, 4, 51, 142, 42, 241, 73, 155, 147, 132, 114,
					104, 242, 87, 8, 4, 37,
				],
				[
					47, 91, 14, 236, 243, 23, 201, 252, 74, 87, 135, 125, 212,
					59, 120, 136, 141, 177, 191, 188, 66, 132, 209, 85, 104,
					114, 29, 191, 181, 240, 187, 34,
				],
				[
					64, 9, 197, 254, 130, 203, 33, 44, 243, 216, 145, 8, 110,
					76, 47, 5, 120, 178, 175, 71, 9, 40, 20, 252, 164, 86, 11,
					147, 230, 9, 55, 1,
				],
				[
					69, 160, 184, 242, 171, 90, 62, 180, 216, 0, 75, 251, 9, 1,
					75, 234, 164, 202, 25, 74, 205, 163, 86, 145, 157, 168, 137,
					11, 190, 106, 252, 22,
				],
				[
					202, 174, 101, 226, 110, 122, 255, 88, 216, 244, 205, 48,
					211, 159, 63, 110, 44, 43, 45, 188, 154, 46, 116, 89, 101,
					121, 94, 176, 210, 23, 167, 1,
				],
				[
					253, 179, 189, 156, 249, 205, 7, 51, 104, 249, 124, 41, 211,
					186, 63, 131, 239, 203, 122, 228, 231, 144, 155, 176, 10,
					19, 34, 245, 241, 228, 181, 27,
				],
				[
					138, 47, 25, 120, 41, 199, 14, 170, 111, 220, 52, 67, 159,
					124, 136, 220, 175, 222, 80, 147, 190, 34, 133, 51, 255,
					136, 48, 36, 151, 36, 11, 25,
				],
				[
					75, 10, 88, 15, 124, 42, 64, 129, 8, 42, 226, 35, 70, 220,
					246, 95, 27, 182, 130, 75, 140, 233, 217, 36, 212, 98, 60,
					165, 250, 235, 4, 14,
				],
				[
					92, 91, 90, 170, 54, 131, 202, 97, 14, 215, 142, 200, 183,
					93, 253, 167, 31, 11, 136, 197, 28, 73, 0, 88, 116, 155,
					164, 15, 244, 77, 226, 11,
				],
				[
					38, 123, 222, 116, 121, 43, 242, 103, 214, 38, 74, 182, 128,
					24, 69, 137, 170, 171, 225, 251, 203, 181, 19, 0, 8, 105,
					88, 56, 180, 196, 65, 32,
				],
				[
					164, 148, 176, 161, 19, 12, 242, 117, 15, 63, 49, 153, 181,
					67, 71, 235, 3, 26, 215, 139, 64, 157, 6, 91, 59, 63, 197,
					216, 165, 193, 213, 22,
				],
				[
					241, 64, 96, 159, 43, 146, 238, 72, 89, 233, 118, 254, 208,
					72, 220, 99, 116, 233, 79, 34, 206, 40, 73, 155, 136, 34,
					109, 84, 130, 87, 65, 19,
				],
				[
					216, 251, 26, 140, 142, 218, 9, 208, 81, 187, 236, 56, 245,
					165, 247, 250, 13, 137, 36, 182, 75, 135, 85, 44, 102, 53,
					35, 37, 66, 66, 25, 33,
				],
				[
					78, 31, 184, 117, 134, 211, 232, 76, 32, 2, 254, 7, 171,
					100, 79, 206, 229, 2, 28, 255, 38, 88, 208, 51, 140, 203,
					15, 208, 138, 89, 179, 29,
				],
			],
			[
				[
					63, 210, 249, 12, 11, 114, 101, 232, 2, 31, 86, 153, 45, 15,
					225, 9, 72, 94, 209, 137, 218, 254, 252, 4, 108, 248, 177,
					209, 254, 41, 255, 45,
				],
				[
					232, 61, 97, 154, 46, 47, 207, 12, 94, 98, 219, 154, 249,
					38, 168, 192, 84, 85, 217, 9, 231, 14, 4, 159, 8, 27, 140,
					45, 165, 156, 65, 47,
				],
				[
					60, 6, 139, 185, 124, 200, 33, 28, 186, 59, 53, 16, 65, 197,
					231, 240, 18, 71, 1, 115, 126, 231, 108, 141, 31, 123, 32,
					91, 252, 2, 110, 4,
				],
				[
					23, 229, 229, 177, 33, 113, 11, 42, 154, 205, 9, 75, 107,
					199, 67, 13, 36, 182, 34, 47, 31, 112, 60, 215, 85, 152, 18,
					214, 179, 106, 75, 44,
				],
				[
					27, 191, 155, 255, 33, 180, 135, 69, 252, 35, 20, 238, 170,
					77, 247, 99, 221, 201, 162, 131, 185, 204, 99, 255, 55, 230,
					40, 110, 193, 37, 237, 30,
				],
				[
					175, 119, 0, 205, 117, 102, 216, 168, 208, 236, 239, 58,
					242, 99, 102, 204, 173, 1, 124, 147, 19, 108, 10, 164, 221,
					20, 217, 251, 15, 125, 195, 45,
				],
				[
					127, 247, 96, 167, 186, 0, 52, 237, 103, 59, 72, 105, 79,
					140, 7, 75, 132, 78, 198, 173, 153, 253, 81, 25, 28, 206,
					68, 221, 250, 234, 219, 30,
				],
				[
					253, 236, 238, 159, 114, 81, 133, 129, 248, 35, 210, 72,
					103, 187, 65, 242, 173, 67, 141, 23, 110, 177, 118, 192,
					191, 147, 50, 11, 224, 98, 137, 37,
				],
				[
					1, 22, 207, 222, 99, 111, 184, 109, 100, 8, 134, 188, 111,
					54, 17, 8, 170, 194, 92, 221, 115, 55, 36, 109, 134, 198,
					116, 3, 104, 204, 205, 28,
				],
				[
					158, 226, 185, 113, 52, 248, 188, 199, 244, 183, 149, 246,
					244, 18, 188, 106, 65, 8, 97, 82, 31, 230, 190, 204, 90, 57,
					103, 207, 140, 76, 144, 10,
				],
				[
					63, 61, 217, 133, 57, 137, 89, 2, 59, 190, 195, 73, 167,
					120, 17, 176, 245, 173, 121, 250, 48, 126, 168, 35, 187, 35,
					178, 172, 30, 50, 166, 28,
				],
				[
					32, 109, 151, 135, 215, 177, 41, 40, 188, 8, 110, 1, 222,
					163, 138, 151, 57, 71, 67, 119, 22, 224, 146, 119, 253, 78,
					48, 226, 145, 59, 214, 29,
				],
				[
					119, 239, 250, 67, 183, 193, 185, 177, 88, 48, 154, 210,
					238, 137, 98, 187, 205, 88, 142, 137, 229, 15, 141, 94, 81,
					103, 243, 190, 181, 237, 168, 14,
				],
				[
					215, 0, 218, 175, 252, 7, 176, 108, 73, 243, 154, 174, 134,
					173, 164, 47, 141, 54, 39, 90, 164, 65, 76, 227, 225, 197,
					104, 71, 69, 170, 228, 7,
				],
				[
					204, 59, 120, 211, 60, 70, 197, 156, 19, 174, 7, 217, 110,
					33, 9, 66, 165, 240, 19, 91, 47, 206, 146, 156, 242, 132,
					131, 59, 138, 55, 72, 4,
				],
				[
					196, 75, 133, 144, 62, 207, 199, 23, 223, 188, 34, 184, 231,
					230, 112, 204, 70, 49, 105, 202, 141, 21, 125, 77, 188, 128,
					219, 7, 242, 106, 141, 47,
				],
				[
					115, 5, 7, 23, 170, 215, 38, 163, 78, 248, 208, 24, 144,
					254, 39, 189, 77, 228, 74, 203, 117, 255, 34, 174, 93, 211,
					94, 52, 220, 39, 44, 23,
				],
			],
			[
				[
					173, 155, 148, 129, 87, 89, 76, 165, 208, 7, 114, 47, 61,
					54, 1, 210, 86, 128, 132, 23, 5, 67, 253, 33, 79, 116, 39,
					203, 84, 228, 31, 27,
				],
				[
					138, 5, 8, 192, 43, 212, 246, 207, 206, 250, 110, 206, 224,
					133, 112, 197, 62, 179, 214, 210, 168, 230, 90, 119, 160,
					168, 16, 169, 34, 183, 57, 4,
				],
				[
					194, 230, 190, 159, 105, 183, 253, 247, 126, 78, 100, 76,
					193, 26, 67, 37, 82, 137, 45, 73, 130, 229, 207, 72, 126,
					214, 150, 109, 162, 95, 155, 21,
				],
				[
					10, 40, 238, 253, 181, 2, 134, 102, 11, 144, 97, 135, 41,
					139, 114, 171, 214, 121, 248, 188, 100, 80, 201, 61, 76, 89,
					121, 148, 233, 139, 227, 15,
				],
				[
					18, 248, 79, 5, 253, 223, 55, 8, 24, 45, 237, 163, 95, 175,
					110, 60, 12, 242, 49, 15, 69, 55, 42, 244, 13, 240, 203, 6,
					235, 210, 80, 14,
				],
				[
					192, 174, 39, 145, 180, 255, 52, 108, 63, 161, 123, 240,
					196, 227, 45, 252, 170, 169, 130, 100, 37, 184, 30, 212,
					105, 202, 230, 173, 14, 105, 112, 28,
				],
				[
					218, 228, 230, 168, 236, 30, 97, 255, 176, 253, 69, 28, 118,
					131, 222, 154, 126, 199, 52, 109, 150, 168, 100, 175, 124,
					172, 161, 193, 241, 7, 184, 40,
				],
				[
					249, 200, 224, 200, 6, 30, 84, 226, 15, 58, 172, 75, 32,
					252, 46, 223, 80, 245, 52, 29, 27, 54, 21, 242, 232, 4, 17,
					90, 80, 65, 92, 4,
				],
				[
					185, 94, 78, 57, 101, 31, 214, 71, 151, 0, 89, 211, 21, 184,
					157, 185, 146, 88, 230, 176, 245, 193, 0, 160, 19, 175, 70,
					60, 39, 64, 195, 0,
				],
				[
					235, 244, 105, 95, 228, 209, 91, 189, 107, 156, 174, 209,
					162, 230, 143, 74, 233, 218, 69, 240, 246, 202, 24, 146, 61,
					179, 118, 198, 90, 230, 21, 45,
				],
				[
					128, 57, 170, 102, 136, 75, 29, 215, 101, 207, 253, 144,
					114, 212, 202, 222, 59, 213, 102, 33, 236, 24, 155, 121,
					166, 163, 152, 84, 139, 41, 198, 41,
				],
				[
					157, 65, 17, 113, 186, 155, 73, 24, 71, 73, 150, 52, 201,
					198, 62, 217, 91, 253, 251, 16, 121, 37, 94, 88, 39, 136,
					41, 231, 10, 207, 60, 0,
				],
				[
					36, 17, 149, 84, 63, 176, 14, 247, 181, 41, 181, 86, 129,
					250, 232, 124, 252, 185, 146, 122, 94, 35, 77, 40, 198, 43,
					208, 1, 138, 192, 160, 29,
				],
				[
					242, 217, 108, 165, 225, 210, 246, 107, 76, 175, 211, 17,
					145, 200, 230, 35, 139, 98, 229, 13, 230, 9, 127, 76, 116,
					177, 35, 76, 163, 128, 70, 2,
				],
				[
					221, 7, 125, 78, 82, 149, 84, 44, 188, 162, 223, 105, 197,
					195, 128, 7, 29, 97, 72, 141, 203, 50, 10, 250, 108, 246,
					76, 144, 57, 148, 138, 34,
				],
				[
					4, 126, 93, 191, 108, 207, 126, 244, 26, 59, 61, 146, 53,
					247, 214, 120, 222, 184, 25, 195, 175, 8, 171, 249, 18, 147,
					236, 0, 124, 134, 117, 19,
				],
				[
					135, 52, 53, 2, 109, 52, 111, 76, 166, 48, 211, 183, 39,
					136, 189, 143, 53, 255, 14, 134, 204, 245, 215, 224, 163,
					191, 14, 100, 138, 8, 77, 31,
				],
			],
			[
				[
					162, 217, 216, 72, 171, 107, 124, 223, 124, 48, 145, 173,
					116, 232, 219, 170, 50, 234, 94, 18, 130, 50, 243, 240, 189,
					189, 92, 154, 219, 93, 192, 6,
				],
				[
					234, 207, 25, 226, 81, 164, 118, 190, 34, 255, 65, 252, 49,
					112, 222, 137, 68, 140, 72, 170, 58, 121, 252, 166, 9, 64,
					248, 6, 206, 27, 111, 3,
				],
				[
					95, 254, 116, 79, 226, 38, 66, 243, 118, 176, 64, 118, 105,
					117, 149, 232, 10, 238, 79, 154, 2, 147, 7, 177, 128, 18,
					52, 230, 77, 138, 174, 27,
				],
				[
					252, 123, 82, 104, 205, 17, 64, 69, 133, 247, 69, 99, 120,
					15, 56, 227, 251, 186, 78, 87, 33, 172, 22, 134, 183, 164,
					163, 168, 232, 206, 205, 26,
				],
				[
					72, 210, 1, 219, 103, 166, 187, 216, 159, 50, 133, 103, 34,
					207, 158, 124, 51, 178, 131, 102, 143, 41, 20, 239, 226,
					195, 85, 108, 112, 185, 143, 47,
				],
				[
					77, 216, 176, 16, 217, 103, 86, 165, 183, 218, 230, 19, 205,
					30, 205, 210, 100, 152, 67, 180, 176, 3, 103, 163, 128, 7,
					3, 37, 209, 126, 3, 48,
				],
				[
					5, 82, 76, 146, 79, 104, 116, 4, 168, 30, 205, 17, 224, 103,
					216, 203, 112, 164, 195, 77, 146, 159, 117, 193, 167, 53,
					14, 85, 147, 228, 14, 36,
				],
				[
					203, 228, 10, 99, 94, 221, 145, 5, 48, 154, 12, 33, 146,
					166, 243, 47, 239, 126, 61, 205, 11, 44, 105, 63, 153, 240,
					254, 241, 239, 102, 46, 38,
				],
				[
					75, 34, 239, 162, 217, 213, 145, 79, 233, 165, 77, 203, 138,
					15, 42, 228, 245, 190, 184, 80, 197, 101, 170, 2, 34, 126,
					17, 87, 25, 89, 16, 44,
				],
				[
					141, 165, 62, 149, 139, 229, 155, 44, 78, 14, 49, 0, 240,
					214, 136, 113, 52, 94, 200, 175, 140, 184, 33, 77, 48, 67,
					95, 107, 223, 165, 16, 2,
				],
				[
					36, 87, 79, 143, 54, 140, 32, 97, 205, 217, 139, 42, 125,
					243, 63, 35, 119, 55, 169, 94, 229, 119, 26, 62, 52, 63,
					143, 177, 70, 218, 125, 4,
				],
				[
					62, 208, 23, 127, 67, 159, 170, 155, 36, 78, 231, 238, 77,
					6, 1, 253, 206, 250, 6, 123, 98, 139, 92, 94, 88, 113, 148,
					47, 57, 93, 218, 22,
				],
				[
					164, 133, 173, 250, 94, 161, 152, 121, 155, 174, 150, 147,
					73, 121, 116, 0, 244, 96, 88, 184, 219, 74, 195, 1, 19, 27,
					182, 88, 130, 33, 37, 33,
				],
				[
					52, 94, 226, 10, 234, 197, 242, 64, 137, 90, 208, 9, 169,
					188, 214, 62, 118, 88, 16, 33, 65, 4, 95, 224, 69, 197, 220,
					92, 163, 95, 219, 21,
				],
				[
					92, 74, 46, 98, 172, 106, 58, 6, 89, 192, 76, 255, 5, 14,
					231, 98, 127, 188, 207, 244, 53, 160, 131, 31, 200, 134,
					194, 178, 131, 195, 78, 13,
				],
				[
					165, 163, 186, 215, 238, 126, 191, 138, 189, 254, 181, 147,
					185, 90, 105, 118, 24, 216, 242, 199, 89, 1, 59, 152, 99,
					74, 122, 136, 224, 135, 151, 17,
				],
				[
					2, 198, 91, 57, 43, 93, 252, 144, 16, 186, 19, 234, 242,
					226, 103, 132, 178, 190, 43, 170, 94, 129, 241, 188, 246,
					217, 230, 39, 114, 253, 213, 5,
				],
			],
			[
				[
					178, 123, 43, 22, 97, 171, 97, 221, 162, 95, 158, 154, 4,
					203, 58, 150, 149, 75, 26, 116, 212, 89, 22, 227, 123, 159,
					191, 92, 203, 240, 164, 37,
				],
				[
					240, 39, 107, 55, 23, 201, 48, 124, 71, 58, 95, 63, 17, 6,
					83, 198, 8, 89, 18, 190, 16, 224, 4, 41, 70, 180, 125, 156,
					95, 1, 16, 26,
				],
				[
					58, 77, 210, 115, 66, 55, 114, 242, 61, 110, 252, 57, 0, 2,
					129, 245, 16, 232, 72, 165, 44, 46, 116, 3, 104, 100, 211,
					29, 92, 196, 224, 12,
				],
				[
					115, 64, 214, 226, 242, 216, 14, 228, 192, 133, 145, 136,
					90, 5, 49, 71, 78, 45, 199, 136, 215, 136, 236, 1, 91, 45,
					136, 141, 58, 157, 181, 11,
				],
				[
					204, 1, 1, 87, 215, 216, 34, 35, 243, 147, 160, 187, 58, 55,
					69, 107, 212, 141, 230, 107, 54, 105, 55, 108, 245, 175,
					246, 166, 212, 59, 137, 5,
				],
				[
					0, 1, 141, 177, 123, 205, 133, 74, 60, 77, 223, 244, 73,
					251, 162, 113, 84, 43, 103, 22, 183, 164, 174, 255, 255,
					197, 152, 170, 231, 108, 232, 41,
				],
				[
					174, 20, 56, 63, 163, 31, 45, 14, 161, 170, 117, 205, 106,
					206, 244, 179, 250, 54, 196, 44, 48, 239, 99, 212, 51, 218,
					227, 238, 142, 50, 129, 42,
				],
				[
					168, 174, 178, 176, 252, 211, 128, 42, 105, 114, 173, 167,
					15, 139, 147, 79, 216, 177, 208, 208, 82, 236, 115, 74, 160,
					119, 51, 243, 98, 33, 35, 44,
				],
				[
					3, 38, 221, 52, 49, 249, 223, 124, 149, 18, 142, 28, 196,
					26, 53, 204, 178, 2, 233, 193, 215, 165, 186, 59, 78, 119,
					208, 208, 182, 202, 75, 23,
				],
				[
					63, 24, 139, 16, 168, 246, 240, 94, 94, 178, 16, 219, 0,
					169, 191, 135, 173, 187, 136, 165, 55, 34, 167, 34, 192,
					189, 7, 37, 146, 88, 156, 8,
				],
				[
					155, 75, 5, 238, 12, 178, 89, 40, 154, 31, 222, 37, 21, 223,
					73, 42, 126, 121, 12, 24, 92, 225, 22, 243, 173, 166, 44,
					171, 166, 222, 54, 40,
				],
				[
					99, 171, 176, 4, 162, 112, 20, 184, 92, 91, 77, 168, 233, 4,
					210, 146, 71, 135, 117, 52, 218, 88, 14, 87, 115, 226, 148,
					175, 68, 233, 207, 31,
				],
				[
					56, 35, 240, 49, 142, 104, 179, 21, 116, 38, 57, 247, 114,
					98, 239, 155, 207, 241, 93, 185, 93, 131, 55, 230, 204, 29,
					212, 65, 60, 198, 179, 42,
				],
				[
					44, 64, 141, 53, 98, 128, 70, 172, 193, 182, 119, 178, 218,
					82, 153, 92, 70, 191, 251, 45, 182, 24, 131, 55, 15, 252,
					64, 138, 121, 17, 108, 42,
				],
				[
					40, 169, 251, 209, 235, 197, 104, 177, 176, 78, 139, 92, 0,
					135, 237, 65, 60, 10, 6, 21, 149, 181, 130, 221, 57, 151,
					144, 179, 151, 119, 47, 28,
				],
				[
					134, 141, 179, 86, 14, 202, 29, 66, 30, 170, 127, 80, 36,
					79, 129, 90, 217, 32, 99, 116, 146, 28, 162, 90, 106, 229,
					253, 149, 101, 66, 26, 36,
				],
				[
					64, 57, 242, 193, 171, 4, 24, 238, 183, 170, 79, 79, 90,
					255, 180, 18, 199, 126, 254, 158, 154, 17, 37, 144, 5, 250,
					23, 180, 112, 147, 23, 35,
				],
			],
			[
				[
					247, 215, 253, 95, 140, 64, 18, 139, 115, 131, 66, 109, 22,
					157, 176, 125, 248, 218, 55, 21, 18, 144, 142, 207, 228,
					199, 255, 80, 99, 62, 102, 37,
				],
				[
					165, 95, 81, 17, 178, 224, 7, 28, 0, 66, 73, 20, 162, 106,
					52, 236, 19, 74, 23, 185, 6, 203, 86, 240, 147, 36, 182, 72,
					248, 35, 158, 12,
				],
				[
					72, 115, 131, 202, 66, 138, 234, 53, 36, 141, 129, 4, 117,
					145, 237, 107, 29, 173, 84, 59, 210, 73, 225, 160, 213, 103,
					188, 111, 117, 72, 248, 1,
				],
				[
					145, 21, 58, 115, 19, 231, 9, 232, 253, 252, 97, 40, 36, 51,
					200, 117, 135, 70, 34, 206, 66, 35, 253, 1, 111, 231, 26,
					40, 6, 107, 245, 29,
				],
				[
					97, 37, 6, 81, 168, 198, 75, 72, 84, 143, 230, 7, 138, 93,
					47, 58, 172, 62, 11, 118, 190, 137, 218, 86, 87, 4, 43, 236,
					203, 33, 227, 30,
				],
				[
					183, 254, 46, 117, 176, 254, 153, 7, 223, 8, 247, 249, 6,
					69, 16, 111, 154, 106, 183, 59, 108, 202, 54, 92, 213, 118,
					1, 22, 111, 73, 38, 34,
				],
				[
					21, 39, 211, 98, 26, 125, 36, 156, 135, 4, 103, 190, 34,
					223, 101, 191, 242, 171, 117, 32, 8, 212, 111, 143, 188,
					244, 216, 156, 68, 83, 232, 9,
				],
				[
					35, 254, 112, 167, 11, 68, 209, 227, 146, 60, 219, 56, 207,
					90, 194, 9, 24, 204, 254, 0, 9, 250, 131, 56, 180, 154, 177,
					150, 181, 4, 145, 21,
				],
				[
					236, 135, 128, 84, 27, 162, 16, 252, 158, 189, 151, 140, 70,
					60, 86, 229, 204, 11, 61, 228, 112, 139, 213, 243, 218, 192,
					80, 96, 134, 151, 144, 37,
				],
				[
					13, 141, 177, 193, 157, 241, 91, 122, 217, 84, 196, 166, 43,
					156, 209, 189, 34, 49, 115, 115, 245, 63, 189, 29, 181, 98,
					18, 84, 230, 196, 240, 6,
				],
				[
					136, 13, 192, 193, 210, 24, 181, 144, 20, 84, 187, 135, 169,
					78, 220, 149, 28, 40, 31, 85, 30, 221, 182, 232, 26, 15, 33,
					174, 174, 168, 145, 35,
				],
				[
					28, 54, 194, 79, 87, 94, 50, 252, 161, 30, 156, 185, 164,
					97, 71, 118, 155, 151, 199, 153, 70, 58, 12, 105, 73, 50,
					100, 66, 139, 103, 181, 37,
				],
				[
					192, 254, 188, 50, 88, 127, 225, 246, 115, 98, 179, 16, 234,
					163, 205, 80, 188, 160, 145, 210, 190, 246, 137, 58, 165,
					64, 47, 202, 239, 233, 23, 5,
				],
				[
					82, 252, 7, 133, 245, 101, 58, 157, 168, 82, 3, 162, 131, 7,
					17, 237, 65, 231, 82, 135, 104, 43, 106, 150, 135, 66, 98,
					174, 70, 133, 126, 11,
				],
				[
					239, 88, 55, 97, 139, 97, 240, 36, 22, 72, 64, 245, 183,
					175, 117, 38, 172, 98, 75, 202, 48, 207, 16, 128, 134, 254,
					197, 109, 76, 98, 69, 20,
				],
				[
					104, 241, 93, 233, 157, 215, 101, 241, 208, 134, 11, 160, 4,
					148, 17, 15, 127, 83, 126, 76, 218, 208, 220, 187, 132, 24,
					136, 142, 144, 147, 91, 42,
				],
				[
					66, 102, 82, 166, 50, 9, 158, 51, 151, 89, 88, 238, 82, 22,
					169, 254, 3, 14, 86, 108, 32, 62, 38, 74, 244, 214, 154, 42,
					147, 153, 240, 35,
				],
			],
			[
				[
					92, 186, 101, 56, 61, 114, 203, 31, 193, 80, 166, 69, 36,
					147, 130, 46, 106, 168, 42, 215, 72, 116, 238, 104, 96, 5,
					124, 60, 175, 217, 76, 2,
				],
				[
					62, 180, 252, 236, 102, 14, 156, 246, 205, 47, 109, 76, 93,
					166, 135, 203, 129, 105, 192, 101, 170, 153, 123, 8, 96,
					174, 130, 251, 34, 101, 157, 10,
				],
				[
					146, 60, 213, 231, 24, 147, 110, 51, 54, 154, 150, 1, 161,
					147, 130, 97, 117, 213, 177, 110, 14, 173, 24, 2, 170, 71,
					15, 1, 66, 31, 145, 8,
				],
				[
					235, 74, 169, 187, 33, 27, 116, 221, 121, 30, 67, 120, 30,
					119, 209, 33, 188, 182, 141, 169, 115, 0, 82, 234, 119, 69,
					38, 220, 145, 31, 63, 17,
				],
				[
					189, 19, 113, 182, 173, 105, 157, 92, 135, 86, 25, 38, 31,
					197, 12, 106, 206, 90, 30, 188, 253, 88, 180, 194, 31, 244,
					39, 251, 121, 84, 215, 17,
				],
				[
					249, 210, 170, 204, 108, 101, 136, 163, 182, 62, 132, 145,
					170, 208, 213, 163, 246, 246, 184, 0, 36, 121, 125, 60, 179,
					167, 46, 205, 25, 180, 129, 18,
				],
				[
					125, 81, 12, 160, 168, 116, 117, 250, 20, 134, 163, 77, 15,
					140, 66, 203, 136, 120, 134, 22, 43, 118, 223, 255, 115, 68,
					220, 47, 183, 219, 33, 32,
				],
				[
					123, 92, 61, 244, 8, 240, 34, 111, 49, 126, 25, 212, 159,
					162, 17, 27, 175, 202, 202, 165, 226, 117, 240, 108, 238,
					109, 122, 17, 229, 72, 192, 36,
				],
				[
					132, 51, 147, 95, 14, 47, 116, 10, 173, 90, 151, 114, 75,
					151, 168, 104, 28, 174, 241, 7, 213, 92, 0, 88, 68, 96, 78,
					233, 60, 248, 99, 45,
				],
				[
					189, 133, 242, 136, 66, 175, 211, 109, 54, 237, 190, 13, 1,
					199, 41, 99, 217, 111, 91, 6, 223, 236, 162, 108, 98, 81,
					85, 74, 201, 79, 64, 6,
				],
				[
					52, 214, 110, 254, 138, 167, 174, 19, 83, 75, 211, 216, 86,
					245, 9, 233, 159, 70, 182, 194, 74, 18, 63, 43, 39, 150,
					220, 35, 242, 158, 251, 14,
				],
				[
					54, 120, 165, 105, 32, 236, 206, 166, 185, 191, 51, 228, 14,
					165, 121, 42, 253, 226, 28, 5, 50, 57, 112, 97, 156, 154,
					126, 129, 39, 120, 211, 8,
				],
				[
					202, 74, 7, 114, 89, 203, 33, 209, 220, 129, 71, 125, 52,
					124, 140, 184, 191, 211, 17, 116, 216, 26, 144, 74, 27, 157,
					79, 131, 192, 125, 163, 0,
				],
				[
					20, 116, 134, 134, 86, 182, 68, 77, 95, 28, 14, 27, 159,
					211, 133, 32, 7, 177, 47, 125, 91, 97, 119, 120, 11, 4, 162,
					238, 94, 216, 58, 24,
				],
				[
					112, 27, 214, 242, 209, 169, 84, 249, 233, 86, 252, 114, 1,
					128, 105, 244, 127, 128, 137, 147, 250, 23, 13, 169, 143,
					151, 155, 61, 204, 181, 80, 8,
				],
				[
					200, 31, 98, 154, 14, 156, 169, 239, 96, 31, 109, 29, 205,
					18, 55, 56, 170, 87, 171, 233, 135, 106, 241, 51, 131, 80,
					249, 2, 211, 133, 222, 15,
				],
				[
					48, 129, 7, 48, 179, 56, 132, 238, 25, 14, 201, 2, 152, 234,
					255, 182, 239, 85, 225, 71, 81, 215, 132, 213, 124, 38, 123,
					72, 108, 63, 86, 33,
				],
			],
			[
				[
					148, 150, 109, 81, 236, 187, 19, 252, 187, 28, 86, 2, 156,
					199, 146, 228, 34, 125, 177, 224, 29, 216, 167, 84, 183,
					244, 245, 155, 20, 188, 173, 18,
				],
				[
					84, 122, 247, 43, 27, 174, 55, 181, 198, 184, 12, 0, 64, 80,
					224, 155, 110, 79, 161, 171, 249, 28, 250, 100, 171, 201,
					89, 220, 136, 49, 226, 27,
				],
				[
					205, 51, 150, 59, 222, 165, 255, 143, 90, 60, 98, 161, 248,
					219, 235, 205, 223, 97, 27, 240, 177, 248, 8, 58, 203, 57,
					254, 40, 64, 94, 81, 44,
				],
				[
					119, 66, 97, 254, 43, 99, 179, 209, 248, 235, 41, 181, 138,
					125, 255, 245, 233, 222, 94, 215, 160, 176, 228, 78, 26, 88,
					228, 167, 160, 238, 41, 32,
				],
				[
					32, 202, 159, 144, 112, 0, 210, 46, 141, 53, 5, 142, 79, 60,
					59, 55, 90, 28, 17, 99, 182, 56, 176, 185, 180, 235, 94,
					211, 245, 148, 169, 35,
				],
				[
					17, 68, 146, 206, 134, 99, 58, 40, 214, 88, 173, 210, 255,
					3, 208, 157, 206, 165, 22, 21, 209, 214, 31, 29, 14, 32,
					252, 134, 220, 227, 249, 44,
				],
				[
					103, 234, 119, 8, 193, 37, 223, 114, 6, 18, 20, 202, 57,
					200, 88, 17, 124, 48, 201, 104, 234, 238, 44, 191, 58, 161,
					153, 200, 63, 98, 28, 28,
				],
				[
					28, 246, 54, 247, 150, 195, 209, 79, 33, 70, 240, 52, 90,
					159, 137, 134, 148, 227, 232, 53, 117, 170, 251, 176, 173,
					112, 186, 123, 239, 130, 4, 28,
				],
				[
					234, 0, 246, 150, 219, 118, 235, 187, 74, 44, 221, 151, 132,
					248, 104, 43, 38, 182, 177, 96, 8, 209, 57, 146, 94, 218,
					149, 47, 114, 52, 195, 21,
				],
				[
					218, 232, 185, 82, 194, 22, 232, 45, 144, 4, 116, 207, 139,
					212, 79, 71, 64, 138, 187, 55, 244, 84, 11, 114, 133, 138,
					93, 29, 130, 92, 17, 32,
				],
				[
					118, 57, 204, 221, 209, 45, 80, 188, 147, 179, 249, 141,
					242, 84, 233, 140, 90, 10, 126, 121, 51, 49, 200, 224, 9,
					169, 28, 206, 248, 128, 246, 46,
				],
				[
					159, 198, 173, 238, 147, 23, 105, 101, 9, 233, 162, 176,
					100, 85, 24, 167, 176, 151, 218, 5, 73, 6, 139, 128, 163,
					60, 106, 86, 46, 163, 238, 39,
				],
				[
					186, 154, 14, 192, 197, 140, 76, 32, 132, 81, 170, 135, 182,
					143, 36, 75, 132, 14, 80, 81, 100, 193, 50, 18, 54, 216, 15,
					162, 215, 100, 113, 31,
				],
				[
					198, 21, 188, 11, 77, 5, 16, 203, 120, 17, 201, 199, 139,
					86, 161, 31, 132, 242, 112, 32, 6, 64, 179, 189, 217, 148,
					126, 126, 11, 185, 87, 5,
				],
				[
					109, 149, 28, 249, 27, 27, 106, 205, 220, 58, 219, 94, 2,
					201, 174, 7, 154, 142, 64, 99, 105, 152, 137, 169, 182, 121,
					0, 133, 135, 242, 216, 24,
				],
				[
					101, 201, 252, 199, 207, 76, 88, 245, 7, 37, 114, 239, 223,
					157, 15, 152, 82, 92, 32, 97, 104, 252, 154, 94, 246, 129,
					233, 206, 160, 7, 75, 39,
				],
				[
					186, 34, 75, 149, 200, 185, 253, 118, 11, 52, 224, 227, 217,
					114, 56, 106, 36, 156, 3, 92, 116, 50, 95, 62, 0, 0, 237,
					227, 232, 1, 15, 31,
				],
			],
			[
				[
					222, 168, 79, 165, 66, 14, 81, 11, 222, 43, 150, 14, 111,
					247, 222, 255, 78, 59, 217, 104, 90, 98, 192, 212, 243, 90,
					192, 206, 39, 205, 109, 46,
				],
				[
					11, 206, 140, 32, 189, 78, 54, 187, 146, 121, 151, 207, 191,
					251, 13, 223, 199, 247, 144, 93, 43, 82, 189, 167, 107, 150,
					231, 210, 48, 119, 147, 31,
				],
				[
					125, 178, 214, 142, 145, 77, 145, 28, 54, 62, 169, 152, 211,
					132, 188, 62, 4, 255, 114, 243, 101, 17, 227, 43, 51, 83,
					133, 131, 2, 75, 23, 14,
				],
				[
					14, 206, 106, 182, 128, 175, 94, 207, 118, 57, 98, 225, 70,
					175, 164, 235, 161, 8, 47, 24, 59, 137, 189, 233, 36, 155,
					5, 78, 177, 94, 158, 16,
				],
				[
					85, 205, 7, 137, 69, 137, 148, 80, 86, 236, 63, 153, 184,
					86, 164, 254, 201, 90, 95, 58, 14, 191, 125, 160, 207, 226,
					82, 3, 46, 81, 97, 13,
				],
				[
					238, 0, 237, 224, 182, 61, 55, 137, 38, 213, 137, 18, 226,
					92, 160, 136, 38, 148, 193, 24, 61, 62, 167, 202, 81, 208,
					161, 151, 179, 161, 143, 43,
				],
				[
					64, 99, 184, 187, 4, 167, 201, 222, 100, 137, 165, 230, 39,
					63, 98, 228, 73, 102, 201, 143, 181, 31, 24, 250, 237, 132,
					227, 196, 122, 125, 183, 13,
				],
				[
					249, 122, 249, 165, 251, 182, 39, 48, 196, 73, 211, 247, 66,
					122, 92, 62, 216, 22, 120, 229, 205, 32, 128, 9, 164, 170,
					210, 118, 248, 170, 208, 36,
				],
				[
					60, 144, 140, 40, 244, 240, 66, 33, 165, 56, 119, 81, 254,
					17, 32, 37, 163, 43, 72, 169, 42, 205, 244, 184, 80, 148,
					150, 43, 59, 66, 139, 27,
				],
				[
					131, 94, 146, 199, 13, 64, 190, 174, 6, 11, 100, 253, 15,
					181, 246, 30, 148, 156, 61, 21, 251, 185, 253, 88, 118, 69,
					141, 57, 208, 58, 8, 30,
				],
				[
					130, 91, 46, 241, 113, 20, 210, 30, 193, 179, 21, 182, 44,
					100, 146, 191, 174, 15, 137, 117, 92, 173, 128, 156, 118,
					89, 155, 249, 222, 235, 136, 17,
				],
				[
					163, 245, 147, 235, 66, 136, 35, 206, 126, 20, 42, 125, 224,
					186, 68, 0, 235, 134, 76, 52, 151, 117, 121, 255, 227, 175,
					226, 134, 114, 114, 72, 12,
				],
				[
					160, 192, 186, 12, 43, 227, 197, 180, 216, 53, 240, 19, 182,
					228, 228, 249, 249, 86, 168, 17, 117, 157, 55, 120, 67, 139,
					184, 179, 195, 174, 13, 18,
				],
				[
					213, 194, 239, 81, 93, 246, 156, 64, 123, 38, 252, 92, 245,
					250, 95, 111, 181, 194, 168, 220, 162, 249, 48, 26, 210, 17,
					122, 23, 13, 195, 106, 35,
				],
				[
					231, 237, 34, 55, 133, 148, 15, 74, 86, 252, 212, 131, 75,
					52, 0, 20, 1, 89, 46, 254, 100, 212, 132, 105, 64, 252, 224,
					116, 6, 38, 62, 5,
				],
				[
					83, 99, 53, 63, 153, 245, 56, 123, 54, 85, 146, 118, 83,
					132, 6, 216, 72, 201, 189, 174, 219, 237, 23, 148, 31, 209,
					56, 107, 216, 65, 76, 24,
				],
				[
					1, 184, 65, 112, 155, 240, 195, 168, 48, 70, 193, 1, 11,
					216, 90, 27, 38, 153, 99, 6, 40, 189, 213, 224, 251, 241,
					229, 89, 62, 12, 130, 28,
				],
			],
			[
				[
					87, 238, 7, 224, 128, 144, 227, 245, 102, 31, 43, 99, 57,
					36, 207, 9, 238, 193, 174, 217, 235, 79, 16, 214, 125, 213,
					69, 51, 217, 135, 39, 7,
				],
				[
					55, 79, 137, 231, 162, 142, 205, 170, 139, 69, 31, 75, 98,
					220, 56, 141, 167, 77, 118, 1, 68, 121, 14, 4, 10, 247, 99,
					194, 177, 208, 188, 18,
				],
				[
					115, 78, 127, 182, 97, 101, 156, 234, 191, 207, 150, 117,
					148, 91, 96, 127, 61, 58, 146, 47, 54, 135, 69, 174, 29,
					232, 154, 48, 11, 75, 90, 7,
				],
				[
					118, 84, 186, 179, 141, 204, 196, 234, 149, 104, 29, 253, 0,
					111, 52, 196, 75, 153, 154, 164, 228, 148, 23, 57, 44, 82,
					69, 174, 154, 244, 37, 5,
				],
				[
					97, 250, 104, 193, 154, 86, 213, 135, 170, 111, 85, 24, 243,
					131, 59, 66, 169, 78, 166, 206, 72, 112, 171, 249, 179, 43,
					14, 129, 131, 250, 56, 46,
				],
				[
					184, 238, 96, 215, 50, 131, 176, 163, 87, 199, 182, 174, 6,
					101, 246, 71, 27, 71, 106, 76, 45, 81, 178, 205, 166, 16,
					174, 49, 190, 158, 232, 6,
				],
				[
					39, 127, 213, 210, 189, 10, 252, 26, 137, 136, 164, 184,
					202, 83, 99, 161, 66, 19, 10, 104, 148, 101, 52, 192, 4,
					185, 95, 68, 79, 146, 144, 11,
				],
				[
					221, 166, 195, 206, 239, 23, 166, 68, 169, 239, 134, 177,
					78, 76, 124, 113, 2, 128, 72, 250, 18, 249, 217, 69, 230,
					249, 63, 245, 120, 28, 224, 2,
				],
				[
					218, 230, 109, 158, 82, 217, 188, 4, 83, 58, 71, 142, 90,
					111, 105, 155, 93, 199, 67, 9, 32, 195, 108, 124, 33, 89,
					153, 100, 16, 4, 153, 10,
				],
				[
					230, 248, 136, 70, 204, 34, 15, 180, 14, 74, 92, 132, 248,
					107, 5, 140, 222, 30, 150, 217, 103, 228, 129, 216, 66, 47,
					247, 158, 10, 173, 123, 24,
				],
				[
					156, 151, 69, 178, 112, 194, 31, 230, 106, 152, 86, 158, 12,
					136, 114, 181, 158, 86, 18, 94, 54, 60, 220, 26, 146, 164,
					196, 67, 200, 10, 173, 44,
				],
				[
					12, 200, 7, 164, 213, 3, 221, 128, 155, 34, 147, 231, 14,
					211, 74, 255, 89, 205, 30, 203, 94, 74, 81, 2, 159, 32, 105,
					81, 86, 64, 110, 2,
				],
				[
					229, 226, 213, 185, 234, 11, 50, 79, 51, 177, 67, 121, 167,
					142, 194, 76, 191, 29, 250, 174, 54, 153, 26, 174, 167, 138,
					125, 225, 180, 109, 9, 7,
				],
				[
					227, 79, 204, 245, 244, 207, 253, 197, 75, 186, 238, 142,
					67, 254, 67, 167, 209, 118, 120, 160, 149, 72, 171, 224, 9,
					27, 203, 102, 67, 223, 58, 48,
				],
				[
					157, 45, 170, 231, 190, 113, 1, 231, 155, 115, 235, 5, 91,
					109, 251, 185, 167, 131, 242, 104, 26, 187, 182, 62, 149,
					245, 106, 48, 20, 23, 255, 32,
				],
				[
					37, 98, 113, 147, 84, 175, 67, 144, 65, 154, 120, 43, 2,
					108, 232, 180, 211, 245, 233, 24, 231, 153, 88, 100, 76, 17,
					167, 164, 114, 53, 197, 16,
				],
				[
					103, 203, 36, 229, 153, 33, 81, 255, 188, 108, 196, 12, 29,
					199, 0, 90, 97, 4, 102, 78, 9, 40, 71, 210, 76, 232, 237,
					138, 163, 172, 51, 10,
				],
			],
			[
				[
					166, 141, 243, 161, 163, 189, 139, 15, 48, 217, 54, 159,
					219, 58, 62, 250, 46, 177, 49, 90, 199, 67, 66, 35, 109,
					198, 237, 124, 188, 167, 16, 46,
				],
				[
					127, 165, 178, 109, 101, 113, 1, 32, 82, 201, 208, 32, 93,
					200, 131, 43, 169, 43, 107, 102, 233, 150, 72, 12, 46, 62,
					215, 69, 78, 221, 53, 25,
				],
				[
					166, 5, 233, 103, 213, 247, 176, 29, 214, 144, 137, 168,
					211, 43, 101, 133, 143, 115, 212, 201, 123, 99, 99, 230,
					170, 62, 40, 203, 129, 252, 229, 24,
				],
				[
					25, 109, 33, 152, 21, 117, 188, 102, 83, 129, 126, 97, 190,
					225, 190, 122, 143, 17, 48, 210, 127, 197, 111, 157, 172,
					115, 55, 146, 50, 66, 145, 22,
				],
				[
					135, 128, 45, 240, 124, 83, 146, 220, 9, 148, 241, 89, 46,
					106, 45, 177, 125, 9, 67, 85, 39, 203, 172, 163, 152, 170,
					97, 228, 196, 73, 239, 37,
				],
				[
					120, 99, 248, 160, 215, 70, 45, 139, 119, 40, 134, 146, 142,
					108, 76, 68, 246, 37, 247, 168, 169, 133, 194, 234, 203,
					227, 131, 128, 244, 23, 70, 12,
				],
				[
					136, 6, 25, 2, 38, 168, 142, 102, 52, 68, 32, 190, 47, 195,
					39, 116, 72, 215, 160, 8, 239, 142, 73, 193, 155, 205, 16,
					141, 222, 137, 153, 36,
				],
				[
					51, 167, 196, 46, 113, 218, 69, 148, 85, 114, 100, 79, 132,
					164, 144, 108, 141, 69, 219, 131, 126, 218, 33, 179, 113,
					39, 47, 146, 77, 133, 189, 46,
				],
				[
					251, 207, 159, 24, 32, 3, 166, 237, 20, 126, 214, 251, 91,
					228, 127, 110, 73, 163, 114, 126, 6, 228, 22, 203, 101, 78,
					44, 110, 156, 78, 168, 20,
				],
				[
					49, 20, 172, 127, 4, 24, 161, 94, 180, 132, 248, 178, 228,
					228, 33, 204, 63, 1, 150, 203, 117, 197, 163, 193, 213, 194,
					93, 74, 230, 109, 8, 3,
				],
				[
					215, 137, 217, 144, 69, 165, 8, 164, 238, 107, 184, 241, 33,
					101, 49, 3, 209, 235, 114, 121, 230, 125, 239, 207, 55, 156,
					222, 128, 194, 160, 255, 43,
				],
				[
					14, 229, 142, 89, 142, 203, 173, 67, 245, 242, 225, 147,
					245, 214, 63, 1, 112, 209, 240, 225, 55, 181, 230, 93, 154,
					208, 118, 179, 9, 13, 133, 3,
				],
				[
					56, 133, 31, 71, 198, 218, 30, 152, 110, 188, 164, 118, 180,
					9, 80, 252, 215, 175, 255, 1, 131, 163, 246, 69, 143, 98,
					86, 58, 153, 56, 180, 24,
				],
				[
					187, 255, 52, 146, 46, 108, 3, 132, 147, 158, 63, 133, 11,
					125, 68, 191, 147, 168, 119, 162, 142, 46, 242, 191, 107,
					239, 15, 64, 7, 171, 11, 35,
				],
				[
					243, 141, 230, 129, 49, 29, 120, 87, 43, 235, 91, 169, 94,
					230, 155, 22, 126, 25, 208, 66, 10, 201, 216, 188, 111, 220,
					158, 31, 235, 188, 223, 41,
				],
				[
					240, 8, 145, 194, 177, 134, 114, 211, 233, 54, 246, 242,
					160, 98, 176, 5, 175, 134, 219, 28, 150, 112, 212, 181, 207,
					54, 87, 101, 188, 120, 83, 2,
				],
				[
					128, 35, 192, 1, 10, 149, 196, 7, 243, 141, 213, 89, 50,
					112, 33, 79, 205, 101, 147, 21, 214, 183, 67, 111, 23, 163,
					129, 26, 196, 96, 106, 17,
				],
			],
			[
				[
					204, 25, 64, 145, 150, 120, 212, 217, 176, 61, 151, 103, 96,
					21, 253, 246, 241, 151, 18, 41, 167, 13, 217, 136, 94, 250,
					82, 153, 123, 28, 19, 6,
				],
				[
					173, 75, 99, 146, 113, 63, 217, 64, 249, 107, 157, 132, 68,
					44, 53, 166, 212, 254, 92, 10, 11, 43, 105, 31, 201, 159,
					150, 166, 48, 182, 163, 12,
				],
				[
					111, 105, 28, 157, 35, 140, 229, 239, 237, 171, 148, 209,
					255, 198, 194, 67, 242, 38, 154, 141, 178, 224, 29, 113,
					171, 120, 169, 18, 240, 194, 70, 11,
				],
				[
					109, 70, 110, 97, 204, 93, 162, 165, 132, 149, 179, 2, 41,
					53, 149, 104, 226, 77, 50, 184, 247, 252, 243, 208, 194,
					252, 52, 179, 54, 107, 126, 31,
				],
				[
					95, 115, 41, 226, 128, 173, 24, 117, 209, 228, 29, 62, 188,
					4, 184, 96, 31, 94, 20, 182, 124, 142, 163, 169, 220, 34,
					70, 54, 194, 212, 46, 32,
				],
				[
					18, 166, 120, 200, 133, 122, 133, 62, 1, 139, 76, 122, 27,
					97, 224, 24, 157, 72, 19, 242, 181, 176, 54, 22, 86, 49,
					178, 250, 97, 111, 104, 25,
				],
				[
					102, 191, 144, 122, 138, 79, 144, 217, 80, 174, 17, 25, 236,
					65, 178, 193, 124, 91, 21, 8, 156, 135, 147, 79, 15, 223,
					77, 120, 213, 104, 79, 43,
				],
				[
					30, 79, 36, 193, 244, 167, 163, 217, 77, 85, 101, 61, 161,
					208, 232, 140, 246, 233, 217, 78, 28, 28, 12, 71, 120, 230,
					169, 19, 57, 40, 100, 20,
				],
				[
					3, 211, 49, 228, 60, 68, 150, 110, 251, 158, 69, 88, 195,
					249, 200, 153, 89, 154, 255, 20, 237, 212, 33, 30, 45, 152,
					72, 215, 123, 90, 39, 6,
				],
				[
					54, 103, 199, 37, 203, 222, 71, 95, 83, 164, 196, 219, 68,
					21, 46, 51, 238, 80, 3, 78, 147, 133, 43, 133, 108, 150,
					196, 91, 193, 194, 239, 33,
				],
				[
					121, 27, 121, 225, 82, 77, 152, 46, 137, 229, 102, 167, 121,
					233, 113, 117, 176, 249, 117, 41, 236, 202, 97, 20, 162, 71,
					148, 244, 249, 186, 84, 45,
				],
				[
					233, 21, 192, 11, 8, 200, 82, 144, 59, 34, 157, 4, 226, 114,
					212, 228, 92, 61, 46, 223, 250, 125, 93, 220, 180, 16, 102,
					33, 77, 126, 239, 16,
				],
				[
					71, 135, 41, 131, 211, 210, 5, 211, 84, 89, 80, 137, 155,
					221, 19, 220, 114, 142, 115, 27, 163, 49, 51, 224, 92, 69,
					71, 66, 228, 44, 145, 29,
				],
				[
					223, 106, 31, 27, 80, 225, 165, 196, 70, 209, 153, 178, 219,
					186, 15, 220, 226, 176, 62, 45, 169, 189, 53, 190, 169, 186,
					250, 144, 178, 200, 232, 17,
				],
				[
					199, 121, 209, 237, 208, 141, 138, 79, 74, 99, 32, 241, 209,
					228, 224, 41, 99, 104, 94, 95, 149, 31, 120, 47, 170, 120,
					131, 212, 22, 23, 145, 41,
				],
				[
					221, 132, 120, 32, 35, 187, 109, 150, 37, 194, 200, 47, 74,
					78, 238, 43, 198, 208, 31, 8, 224, 63, 128, 154, 179, 6, 57,
					249, 164, 224, 146, 42,
				],
				[
					71, 134, 67, 206, 89, 126, 156, 224, 131, 87, 162, 24, 49,
					148, 91, 1, 232, 236, 41, 244, 86, 35, 63, 221, 174, 25,
					202, 112, 42, 24, 115, 45,
				],
			],
			[
				[
					153, 247, 93, 78, 194, 63, 75, 2, 116, 172, 22, 85, 53, 255,
					132, 35, 74, 116, 211, 75, 159, 132, 150, 195, 53, 107, 153,
					1, 111, 68, 206, 38,
				],
				[
					36, 95, 100, 18, 90, 132, 162, 80, 249, 148, 162, 20, 191,
					152, 31, 146, 93, 195, 29, 76, 42, 3, 120, 163, 113, 105,
					50, 132, 12, 218, 245, 36,
				],
				[
					190, 113, 172, 45, 78, 27, 122, 78, 230, 151, 207, 111, 183,
					46, 227, 123, 176, 52, 25, 201, 92, 58, 207, 31, 135, 152,
					59, 76, 154, 238, 126, 26,
				],
				[
					201, 203, 169, 130, 231, 194, 70, 45, 38, 16, 131, 124, 210,
					140, 162, 51, 80, 119, 89, 18, 33, 117, 108, 93, 0, 3, 176,
					3, 171, 165, 123, 38,
				],
				[
					222, 51, 14, 128, 56, 64, 213, 235, 139, 194, 174, 135, 48,
					152, 130, 153, 57, 117, 63, 103, 86, 118, 215, 55, 38, 158,
					251, 212, 75, 170, 156, 5,
				],
				[
					179, 58, 82, 119, 34, 188, 136, 45, 78, 243, 182, 74, 133,
					51, 39, 189, 135, 92, 150, 59, 140, 120, 201, 115, 209, 249,
					33, 220, 5, 178, 39, 25,
				],
				[
					98, 155, 160, 122, 135, 121, 53, 192, 111, 62, 130, 159, 82,
					1, 127, 18, 102, 171, 152, 141, 238, 22, 193, 144, 17, 62,
					113, 177, 142, 177, 78, 27,
				],
				[
					120, 166, 87, 34, 247, 130, 113, 117, 81, 37, 236, 243, 230,
					108, 67, 224, 239, 40, 14, 9, 122, 205, 23, 42, 181, 10,
					160, 159, 218, 51, 22, 0,
				],
				[
					229, 55, 151, 174, 168, 164, 217, 74, 207, 236, 196, 43,
					253, 178, 4, 238, 21, 27, 223, 22, 81, 181, 191, 164, 48,
					71, 204, 182, 154, 160, 159, 0,
				],
				[
					187, 95, 139, 158, 198, 229, 49, 144, 157, 123, 172, 40,
					139, 45, 155, 96, 124, 217, 148, 145, 23, 66, 151, 2, 214,
					159, 7, 214, 68, 122, 23, 9,
				],
				[
					25, 64, 242, 76, 123, 102, 252, 214, 173, 183, 40, 188, 9,
					12, 217, 114, 39, 137, 135, 86, 158, 157, 135, 94, 206, 193,
					47, 145, 77, 106, 182, 11,
				],
				[
					195, 233, 20, 198, 255, 213, 124, 96, 9, 146, 236, 188, 233,
					55, 244, 166, 81, 45, 90, 72, 182, 56, 52, 162, 218, 197,
					36, 120, 99, 194, 66, 4,
				],
				[
					44, 86, 158, 32, 100, 194, 172, 166, 152, 60, 171, 250, 43,
					224, 64, 185, 139, 146, 18, 36, 61, 166, 91, 233, 152, 154,
					98, 104, 179, 18, 17, 22,
				],
				[
					227, 151, 3, 83, 46, 17, 88, 25, 20, 161, 18, 59, 52, 226,
					0, 154, 52, 4, 30, 172, 218, 242, 147, 226, 177, 128, 59,
					64, 214, 81, 204, 29,
				],
				[
					61, 100, 142, 199, 179, 215, 108, 238, 216, 156, 243, 249,
					185, 169, 48, 245, 99, 108, 1, 237, 192, 90, 186, 186, 15,
					25, 22, 199, 15, 45, 32, 3,
				],
				[
					203, 16, 121, 76, 83, 92, 241, 7, 48, 14, 146, 102, 84, 139,
					103, 149, 179, 240, 35, 124, 126, 157, 134, 40, 94, 215, 86,
					159, 206, 27, 88, 28,
				],
				[
					16, 171, 64, 146, 193, 247, 14, 88, 91, 246, 27, 225, 186,
					32, 23, 32, 139, 135, 122, 176, 230, 74, 217, 110, 66, 243,
					155, 223, 151, 4, 173, 11,
				],
			],
			[
				[
					139, 222, 163, 8, 50, 10, 125, 204, 28, 165, 242, 81, 229,
					123, 169, 39, 156, 102, 4, 244, 4, 75, 33, 144, 91, 150, 51,
					236, 232, 194, 199, 22,
				],
				[
					234, 20, 125, 76, 128, 104, 162, 173, 120, 243, 149, 54,
					164, 26, 122, 202, 195, 172, 177, 210, 221, 143, 113, 189,
					40, 76, 126, 229, 71, 90, 13, 13,
				],
				[
					206, 234, 101, 157, 7, 172, 44, 4, 253, 5, 109, 219, 82,
					175, 26, 142, 202, 44, 241, 32, 62, 24, 19, 31, 242, 80,
					239, 151, 188, 102, 165, 20,
				],
				[
					173, 5, 33, 242, 9, 91, 159, 218, 97, 238, 39, 140, 243,
					195, 29, 220, 17, 144, 101, 130, 219, 71, 19, 88, 180, 141,
					47, 254, 222, 53, 10, 44,
				],
				[
					127, 178, 16, 153, 167, 44, 26, 67, 16, 96, 10, 60, 113, 82,
					15, 169, 241, 20, 56, 153, 34, 254, 97, 214, 164, 197, 137,
					61, 201, 147, 131, 12,
				],
				[
					56, 148, 48, 6, 67, 198, 203, 198, 143, 38, 78, 78, 220, 26,
					223, 96, 92, 1, 118, 173, 169, 172, 252, 143, 93, 63, 217,
					30, 46, 200, 48, 15,
				],
				[
					135, 43, 115, 240, 33, 210, 88, 83, 136, 7, 102, 50, 96,
					181, 133, 233, 246, 225, 231, 36, 235, 149, 130, 153, 153,
					197, 43, 188, 193, 249, 219, 27,
				],
				[
					214, 22, 108, 93, 186, 105, 232, 234, 106, 29, 27, 18, 77,
					21, 248, 134, 243, 155, 128, 188, 19, 122, 96, 178, 24, 71,
					213, 98, 196, 135, 203, 7,
				],
				[
					54, 3, 56, 180, 26, 22, 126, 254, 214, 149, 189, 165, 211,
					204, 52, 164, 3, 67, 221, 193, 130, 71, 68, 192, 97, 194,
					58, 198, 42, 99, 201, 19,
				],
				[
					62, 181, 19, 209, 145, 133, 144, 118, 22, 114, 14, 7, 84,
					190, 46, 61, 122, 237, 56, 165, 106, 145, 144, 31, 200, 140,
					53, 155, 157, 50, 132, 1,
				],
				[
					62, 56, 2, 112, 12, 42, 64, 113, 127, 88, 51, 218, 105, 60,
					151, 61, 200, 208, 95, 161, 182, 133, 255, 176, 210, 102,
					250, 201, 191, 208, 85, 36,
				],
				[
					96, 78, 229, 194, 178, 140, 2, 92, 232, 219, 21, 71, 64, 91,
					150, 45, 52, 106, 183, 200, 120, 150, 171, 109, 5, 66, 130,
					141, 70, 40, 30, 26,
				],
				[
					2, 137, 129, 155, 225, 192, 163, 225, 235, 88, 43, 119, 24,
					106, 134, 154, 207, 237, 99, 244, 170, 61, 52, 112, 163,
					102, 73, 49, 138, 237, 253, 15,
				],
				[
					36, 107, 99, 70, 111, 115, 119, 65, 77, 180, 126, 140, 251,
					61, 250, 230, 249, 220, 254, 100, 83, 137, 138, 43, 177,
					214, 38, 125, 177, 205, 23, 9,
				],
				[
					38, 171, 62, 210, 231, 215, 114, 191, 126, 30, 120, 36, 74,
					131, 196, 203, 44, 70, 2, 124, 124, 86, 12, 235, 95, 77,
					138, 221, 129, 140, 60, 43,
				],
				[
					41, 146, 32, 25, 112, 165, 155, 218, 170, 155, 90, 38, 116,
					221, 245, 239, 32, 82, 201, 12, 229, 230, 186, 5, 227, 90,
					106, 173, 21, 50, 13, 39,
				],
				[
					187, 44, 51, 121, 198, 38, 232, 183, 21, 32, 27, 242, 224,
					219, 102, 5, 141, 225, 83, 168, 118, 222, 229, 160, 62, 57,
					8, 38, 244, 5, 76, 9,
				],
			],
		],
		preSparseMds: [
			[
				[
					91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228, 101,
					147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185, 133, 145,
					82, 177, 17, 34, 22, 8,
				],
				[
					148, 155, 245, 18, 213, 66, 52, 6, 253, 149, 30, 99, 62, 7,
					110, 250, 157, 199, 250, 4, 45, 228, 62, 26, 59, 77, 47,
					226, 147, 171, 127, 5,
				],
				[
					84, 92, 70, 226, 64, 19, 10, 220, 103, 122, 171, 11, 227,
					38, 218, 19, 54, 45, 204, 199, 20, 203, 32, 67, 93, 86, 119,
					58, 118, 232, 11, 29,
				],
				[
					111, 133, 150, 243, 83, 74, 102, 163, 28, 51, 30, 254, 209,
					235, 88, 91, 10, 162, 177, 38, 186, 202, 150, 188, 253, 133,
					175, 152, 187, 65, 131, 24,
				],
				[
					208, 141, 223, 214, 116, 40, 45, 40, 38, 70, 17, 254, 129,
					144, 25, 102, 127, 159, 174, 104, 144, 87, 123, 156, 89,
					185, 156, 72, 171, 174, 151, 1,
				],
				[
					137, 168, 125, 99, 16, 158, 75, 115, 45, 0, 115, 225, 216,
					50, 28, 219, 155, 134, 141, 116, 91, 165, 135, 38, 102, 5,
					228, 249, 146, 125, 116, 45,
				],
				[
					56, 106, 10, 12, 230, 94, 200, 78, 181, 187, 209, 56, 254,
					56, 114, 62, 241, 182, 27, 245, 87, 191, 130, 59, 140, 201,
					36, 186, 187, 85, 171, 33,
				],
				[
					32, 131, 248, 5, 209, 17, 141, 252, 196, 36, 28, 225, 46,
					242, 160, 219, 202, 235, 72, 42, 60, 59, 185, 79, 255, 135,
					138, 33, 113, 12, 121, 0,
				],
				[
					186, 250, 134, 176, 101, 153, 237, 245, 179, 108, 79, 20,
					28, 251, 27, 181, 41, 148, 191, 44, 226, 183, 16, 94, 162,
					234, 208, 35, 46, 155, 73, 29,
				],
				[
					218, 171, 30, 172, 79, 13, 253, 147, 195, 220, 207, 153,
					127, 180, 12, 113, 248, 163, 192, 194, 86, 87, 183, 155,
					116, 248, 3, 62, 251, 225, 31, 24,
				],
				[
					132, 67, 56, 189, 234, 169, 13, 249, 170, 3, 103, 36, 45,
					175, 133, 236, 220, 14, 26, 155, 238, 160, 88, 109, 22, 122,
					152, 91, 173, 233, 154, 16,
				],
				[
					177, 210, 179, 16, 42, 153, 167, 81, 113, 46, 108, 152, 63,
					202, 189, 77, 215, 204, 144, 58, 184, 252, 151, 129, 20,
					250, 42, 63, 146, 23, 136, 15,
				],
				[
					21, 205, 63, 232, 120, 107, 160, 163, 143, 198, 88, 171, 58,
					127, 85, 74, 205, 132, 46, 9, 195, 76, 55, 113, 255, 250,
					188, 15, 133, 196, 191, 5,
				],
				[
					182, 81, 253, 171, 216, 222, 185, 71, 246, 55, 33, 195, 147,
					240, 14, 62, 190, 144, 26, 36, 106, 25, 83, 120, 102, 123,
					33, 193, 204, 114, 32, 45,
				],
				[
					208, 189, 211, 138, 74, 142, 238, 120, 252, 138, 154, 26,
					12, 237, 136, 29, 193, 9, 185, 194, 186, 135, 80, 239, 226,
					160, 220, 182, 141, 25, 20, 8,
				],
				[
					95, 195, 150, 105, 76, 26, 81, 173, 250, 142, 97, 51, 222,
					217, 223, 162, 14, 71, 45, 120, 68, 67, 123, 188, 109, 220,
					126, 215, 213, 140, 216, 31,
				],
				[
					123, 166, 111, 13, 143, 79, 117, 203, 246, 152, 96, 169, 34,
					175, 6, 189, 54, 53, 19, 112, 58, 125, 247, 97, 250, 120,
					249, 180, 37, 91, 143, 7,
				],
			],
			[
				[
					229, 28, 225, 78, 43, 221, 184, 9, 177, 63, 172, 254, 53, 1,
					215, 196, 251, 67, 99, 160, 46, 37, 75, 156, 224, 33, 63,
					42, 141, 255, 72, 0,
				],
				[
					154, 70, 39, 97, 166, 203, 124, 238, 147, 199, 36, 161, 172,
					16, 103, 27, 123, 56, 41, 174, 22, 211, 142, 246, 124, 221,
					159, 72, 217, 29, 1, 34,
				],
				[
					39, 64, 3, 199, 232, 160, 97, 32, 47, 80, 85, 174, 164, 200,
					151, 204, 2, 232, 160, 149, 189, 224, 91, 75, 240, 141, 92,
					204, 64, 230, 120, 43,
				],
				[
					24, 166, 226, 175, 104, 236, 152, 62, 60, 17, 217, 219, 179,
					114, 159, 4, 97, 255, 106, 218, 142, 165, 175, 202, 187,
					104, 245, 79, 17, 203, 41, 9,
				],
				[
					103, 81, 177, 231, 74, 219, 29, 124, 21, 71, 132, 214, 219,
					118, 206, 87, 236, 150, 166, 107, 11, 163, 101, 61, 128,
					233, 40, 231, 59, 234, 186, 26,
				],
				[
					161, 132, 229, 166, 17, 64, 191, 167, 237, 133, 196, 33,
					250, 139, 179, 215, 207, 107, 185, 36, 203, 110, 222, 173,
					232, 169, 242, 11, 189, 113, 58, 19,
				],
				[
					91, 134, 63, 82, 82, 182, 27, 158, 160, 244, 190, 46, 120,
					72, 154, 191, 45, 68, 120, 77, 226, 246, 160, 169, 4, 175,
					93, 112, 9, 223, 160, 24,
				],
				[
					47, 73, 34, 20, 230, 92, 212, 16, 43, 175, 18, 216, 197, 35,
					120, 162, 73, 59, 15, 77, 127, 121, 195, 205, 94, 212, 27,
					194, 37, 234, 253, 22,
				],
				[
					94, 11, 129, 194, 41, 129, 34, 6, 123, 94, 242, 91, 207,
					154, 168, 44, 203, 121, 168, 96, 235, 193, 239, 183, 47, 80,
					113, 154, 123, 146, 235, 41,
				],
				[
					171, 106, 186, 38, 81, 223, 36, 20, 181, 165, 33, 140, 4,
					174, 191, 9, 218, 210, 0, 109, 116, 116, 98, 108, 90, 67,
					173, 217, 35, 125, 20, 4,
				],
				[
					213, 182, 32, 220, 156, 222, 198, 157, 221, 130, 252, 219,
					83, 150, 149, 214, 116, 95, 137, 201, 247, 155, 225, 234,
					154, 116, 138, 216, 133, 43, 139, 40,
				],
				[
					54, 57, 96, 224, 5, 155, 9, 3, 10, 83, 76, 70, 215, 205,
					183, 219, 221, 71, 99, 254, 24, 52, 65, 34, 171, 141, 13, 6,
					245, 136, 170, 46,
				],
				[
					247, 52, 148, 91, 213, 2, 211, 21, 101, 120, 198, 82, 98,
					245, 145, 89, 14, 125, 109, 215, 254, 157, 227, 252, 98,
					194, 154, 116, 62, 192, 127, 47,
				],
				[
					68, 237, 190, 192, 14, 222, 15, 164, 7, 229, 122, 40, 199,
					13, 239, 253, 233, 109, 86, 247, 43, 171, 125, 190, 34, 93,
					63, 72, 174, 196, 86, 5,
				],
				[
					44, 46, 134, 162, 187, 61, 209, 169, 153, 57, 112, 115, 47,
					222, 19, 125, 77, 23, 116, 132, 1, 84, 219, 228, 82, 43, 0,
					216, 36, 198, 96, 7,
				],
				[
					70, 23, 57, 126, 158, 17, 216, 222, 92, 241, 7, 165, 12, 20,
					6, 154, 240, 210, 254, 52, 207, 233, 61, 53, 105, 0, 159,
					77, 163, 177, 108, 35,
				],
				[
					36, 42, 146, 20, 159, 251, 111, 131, 198, 87, 240, 150, 7,
					7, 166, 32, 40, 75, 226, 87, 183, 54, 216, 217, 142, 227,
					124, 92, 65, 27, 182, 43,
				],
			],
			[
				[
					251, 82, 145, 244, 254, 108, 41, 74, 2, 186, 182, 212, 152,
					79, 77, 122, 24, 111, 238, 73, 110, 154, 111, 176, 55, 135,
					170, 211, 163, 190, 207, 12,
				],
				[
					98, 96, 81, 49, 61, 220, 81, 192, 209, 99, 1, 201, 248, 238,
					247, 146, 21, 67, 5, 123, 200, 59, 109, 153, 176, 10, 30,
					16, 167, 230, 35, 26,
				],
				[
					9, 67, 47, 2, 115, 41, 71, 174, 115, 243, 204, 98, 230, 150,
					52, 53, 219, 137, 90, 67, 139, 242, 79, 11, 105, 114, 82,
					230, 249, 73, 186, 19,
				],
				[
					216, 96, 139, 212, 150, 112, 4, 184, 41, 205, 12, 169, 25,
					239, 192, 88, 136, 26, 191, 244, 204, 168, 54, 117, 44, 129,
					24, 230, 40, 35, 59, 46,
				],
				[
					92, 80, 86, 105, 152, 164, 78, 224, 77, 126, 50, 190, 64,
					17, 14, 192, 6, 86, 41, 120, 44, 168, 179, 128, 110, 40,
					152, 122, 34, 255, 181, 40,
				],
				[
					84, 77, 240, 211, 207, 167, 254, 203, 121, 190, 200, 134,
					63, 254, 175, 165, 138, 115, 107, 179, 108, 91, 66, 113, 33,
					105, 139, 134, 227, 73, 188, 40,
				],
				[
					104, 147, 203, 228, 84, 144, 253, 117, 80, 40, 180, 65, 32,
					17, 3, 16, 117, 47, 35, 32, 137, 3, 226, 243, 34, 155, 34,
					185, 110, 132, 190, 18,
				],
				[
					243, 238, 90, 208, 230, 111, 156, 33, 61, 44, 248, 254, 107,
					91, 111, 238, 107, 126, 112, 90, 134, 181, 11, 178, 173,
					189, 27, 104, 105, 69, 180, 32,
				],
				[
					155, 251, 191, 254, 151, 104, 195, 121, 67, 188, 180, 163,
					255, 101, 120, 71, 218, 16, 202, 26, 157, 167, 213, 42, 49,
					69, 188, 57, 127, 116, 109, 2,
				],
				[
					34, 107, 56, 118, 175, 64, 120, 16, 201, 65, 204, 206, 197,
					8, 45, 167, 179, 51, 94, 143, 255, 105, 236, 48, 75, 211,
					69, 67, 123, 99, 152, 38,
				],
				[
					56, 131, 27, 32, 153, 232, 136, 140, 101, 202, 125, 165,
					137, 28, 148, 71, 80, 111, 137, 28, 160, 200, 27, 212, 10,
					194, 161, 195, 183, 219, 154, 8,
				],
				[
					113, 108, 19, 187, 25, 120, 55, 168, 3, 254, 46, 197, 237,
					65, 26, 20, 101, 42, 4, 189, 234, 252, 22, 225, 230, 80,
					157, 235, 103, 24, 18, 20,
				],
				[
					175, 8, 129, 164, 75, 94, 67, 19, 118, 36, 149, 144, 175,
					130, 75, 175, 41, 176, 22, 115, 8, 41, 248, 12, 108, 88,
					183, 251, 137, 147, 156, 19,
				],
				[
					73, 58, 22, 89, 239, 113, 58, 149, 18, 226, 10, 61, 113,
					185, 124, 36, 48, 165, 16, 161, 30, 146, 43, 66, 196, 107,
					152, 219, 153, 18, 9, 48,
				],
				[
					133, 13, 135, 217, 214, 153, 241, 187, 93, 81, 129, 109,
					189, 33, 95, 24, 142, 168, 89, 90, 108, 77, 235, 178, 135,
					76, 66, 110, 72, 174, 101, 40,
				],
				[
					218, 67, 86, 102, 157, 245, 248, 10, 90, 12, 67, 70, 87,
					219, 57, 126, 199, 101, 251, 152, 129, 244, 42, 250, 184,
					34, 98, 224, 193, 32, 33, 11,
				],
				[
					75, 154, 240, 42, 253, 64, 168, 102, 20, 41, 77, 201, 46,
					194, 83, 232, 151, 103, 109, 124, 97, 164, 19, 224, 124, 26,
					85, 169, 62, 103, 188, 24,
				],
			],
			[
				[
					196, 88, 64, 89, 145, 148, 165, 44, 200, 71, 65, 125, 109,
					155, 86, 244, 173, 74, 125, 172, 233, 108, 112, 216, 112,
					255, 180, 147, 98, 179, 204, 20,
				],
				[
					154, 241, 5, 59, 49, 154, 211, 45, 193, 179, 156, 157, 11,
					103, 215, 251, 15, 237, 127, 39, 43, 130, 243, 57, 32, 114,
					179, 120, 70, 164, 235, 4,
				],
				[
					89, 255, 105, 178, 46, 12, 135, 68, 163, 94, 240, 82, 139,
					68, 189, 240, 106, 223, 180, 129, 249, 207, 49, 49, 91, 6,
					111, 34, 154, 103, 154, 2,
				],
				[
					156, 244, 48, 35, 52, 13, 83, 129, 74, 247, 214, 109, 246,
					195, 128, 150, 81, 124, 61, 219, 133, 63, 25, 142, 216, 212,
					63, 108, 130, 153, 145, 12,
				],
				[
					83, 201, 149, 99, 46, 190, 236, 93, 194, 144, 19, 227, 77,
					175, 183, 170, 12, 110, 200, 5, 18, 203, 151, 183, 1, 227,
					74, 77, 237, 158, 77, 14,
				],
				[
					7, 175, 170, 216, 62, 196, 27, 48, 232, 34, 120, 140, 151,
					240, 0, 155, 42, 160, 173, 153, 209, 68, 128, 41, 56, 65,
					241, 65, 127, 167, 53, 40,
				],
				[
					247, 187, 136, 119, 222, 65, 62, 86, 49, 182, 53, 125, 76,
					240, 31, 200, 172, 90, 80, 125, 35, 69, 233, 88, 141, 216,
					247, 160, 171, 130, 126, 13,
				],
				[
					23, 32, 162, 206, 42, 59, 218, 26, 59, 49, 46, 8, 35, 150,
					108, 186, 91, 129, 153, 171, 187, 254, 181, 53, 16, 226, 43,
					6, 37, 7, 91, 45,
				],
				[
					246, 212, 221, 208, 209, 236, 21, 129, 73, 249, 153, 55, 61,
					236, 91, 0, 145, 168, 31, 200, 59, 243, 112, 39, 247, 252,
					15, 26, 146, 215, 191, 44,
				],
				[
					154, 128, 50, 85, 197, 77, 156, 46, 244, 3, 123, 162, 212,
					83, 124, 223, 12, 60, 45, 231, 6, 153, 121, 165, 95, 129,
					86, 130, 248, 240, 215, 29,
				],
				[
					32, 162, 108, 27, 240, 83, 139, 173, 86, 52, 254, 189, 47,
					117, 15, 242, 227, 135, 5, 224, 120, 44, 69, 201, 235, 193,
					194, 91, 107, 148, 86, 15,
				],
				[
					76, 73, 28, 240, 185, 132, 19, 243, 208, 141, 214, 225, 141,
					151, 199, 231, 59, 199, 14, 130, 80, 233, 26, 4, 8, 9, 124,
					92, 18, 29, 67, 12,
				],
				[
					47, 27, 169, 127, 48, 158, 202, 144, 0, 209, 32, 35, 10,
					219, 38, 52, 116, 234, 227, 106, 23, 133, 182, 181, 139,
					167, 240, 156, 139, 151, 44, 22,
				],
				[
					48, 127, 194, 53, 25, 33, 168, 94, 188, 86, 90, 250, 111,
					191, 253, 201, 237, 232, 153, 85, 145, 43, 161, 84, 49, 215,
					126, 5, 198, 246, 118, 15,
				],
				[
					8, 61, 255, 56, 88, 176, 195, 8, 140, 13, 110, 69, 204, 218,
					170, 94, 84, 88, 27, 122, 67, 86, 211, 233, 206, 203, 196,
					160, 121, 217, 244, 47,
				],
				[
					62, 246, 91, 205, 37, 89, 37, 200, 253, 51, 200, 108, 181,
					99, 91, 108, 44, 161, 0, 248, 151, 23, 41, 199, 215, 40,
					227, 67, 89, 203, 109, 46,
				],
				[
					229, 241, 131, 96, 82, 193, 199, 116, 59, 143, 175, 9, 83,
					167, 13, 15, 83, 2, 125, 193, 165, 87, 10, 179, 129, 223,
					218, 36, 165, 202, 104, 16,
				],
			],
			[
				[
					6, 99, 217, 59, 212, 149, 147, 58, 137, 131, 165, 176, 147,
					208, 187, 196, 27, 108, 186, 28, 59, 10, 184, 243, 112, 10,
					53, 13, 100, 245, 14, 28,
				],
				[
					101, 248, 150, 137, 9, 116, 205, 165, 39, 114, 160, 12, 112,
					89, 113, 207, 225, 124, 74, 68, 148, 21, 181, 26, 34, 165,
					206, 73, 253, 197, 4, 35,
				],
				[
					180, 154, 148, 176, 24, 24, 76, 149, 66, 185, 57, 130, 53,
					94, 123, 205, 54, 30, 109, 93, 66, 69, 141, 8, 207, 56, 119,
					138, 107, 250, 76, 13,
				],
				[
					24, 234, 63, 45, 110, 204, 210, 253, 170, 9, 179, 181, 67,
					20, 48, 51, 112, 237, 78, 232, 161, 185, 161, 166, 25, 12,
					120, 101, 183, 73, 44, 31,
				],
				[
					24, 187, 39, 180, 156, 49, 78, 29, 92, 222, 27, 53, 104, 59,
					101, 182, 157, 110, 68, 243, 163, 96, 86, 109, 137, 167, 93,
					149, 86, 222, 122, 9,
				],
				[
					197, 148, 115, 252, 56, 66, 204, 240, 243, 65, 212, 166, 54,
					78, 234, 120, 254, 104, 26, 210, 137, 145, 231, 17, 219,
					200, 255, 44, 217, 13, 38, 31,
				],
				[
					184, 221, 170, 102, 119, 136, 244, 169, 17, 76, 130, 156,
					21, 201, 237, 9, 125, 82, 68, 20, 3, 249, 232, 9, 235, 216,
					220, 3, 197, 81, 51, 16,
				],
				[
					145, 194, 102, 28, 105, 0, 189, 113, 55, 213, 96, 47, 83,
					75, 222, 246, 215, 206, 209, 95, 189, 236, 220, 154, 238,
					255, 15, 224, 97, 237, 238, 18,
				],
				[
					122, 98, 213, 115, 142, 138, 92, 206, 63, 228, 12, 33, 72,
					24, 88, 156, 85, 132, 76, 107, 141, 210, 207, 80, 86, 212,
					79, 218, 125, 20, 231, 31,
				],
				[
					5, 62, 61, 205, 217, 35, 139, 220, 187, 153, 183, 228, 221,
					35, 140, 81, 43, 134, 67, 173, 32, 65, 53, 233, 180, 244,
					86, 209, 217, 1, 208, 37,
				],
				[
					67, 204, 97, 111, 46, 252, 76, 170, 26, 68, 94, 207, 185,
					196, 87, 46, 19, 28, 134, 1, 5, 220, 117, 13, 54, 237, 151,
					104, 113, 43, 210, 22,
				],
				[
					200, 202, 93, 158, 150, 183, 154, 19, 19, 233, 239, 198,
					244, 251, 61, 111, 194, 50, 213, 42, 47, 61, 112, 109, 195,
					223, 198, 19, 106, 158, 155, 11,
				],
				[
					84, 50, 221, 50, 103, 218, 193, 123, 128, 79, 134, 119, 65,
					181, 173, 128, 108, 150, 217, 47, 90, 232, 135, 57, 145, 64,
					223, 165, 242, 228, 119, 19,
				],
				[
					143, 100, 225, 40, 243, 94, 145, 195, 233, 36, 18, 224, 143,
					163, 33, 68, 153, 13, 22, 254, 12, 221, 161, 192, 33, 156,
					80, 251, 240, 115, 245, 10,
				],
				[
					178, 124, 6, 191, 50, 65, 88, 157, 125, 80, 185, 238, 196,
					15, 119, 216, 1, 124, 175, 138, 13, 253, 253, 194, 184, 4,
					112, 97, 108, 227, 19, 47,
				],
				[
					4, 29, 140, 233, 105, 87, 163, 210, 31, 81, 12, 7, 73, 161,
					228, 53, 73, 178, 221, 144, 197, 185, 100, 191, 33, 3, 179,
					81, 148, 134, 139, 18,
				],
				[
					35, 110, 225, 20, 254, 92, 88, 195, 119, 120, 215, 65, 182,
					62, 183, 2, 91, 207, 239, 225, 14, 93, 216, 247, 93, 52,
					173, 49, 177, 45, 59, 16,
				],
			],
			[
				[
					153, 115, 92, 36, 179, 81, 162, 46, 144, 229, 26, 41, 62,
					64, 141, 60, 60, 66, 203, 148, 197, 138, 126, 58, 126, 111,
					139, 129, 16, 139, 80, 17,
				],
				[
					164, 67, 117, 55, 110, 255, 239, 191, 85, 223, 172, 215,
					205, 81, 18, 222, 28, 112, 121, 120, 56, 37, 7, 85, 8, 30,
					61, 155, 148, 100, 203, 5,
				],
				[
					179, 228, 89, 81, 129, 233, 87, 205, 36, 39, 188, 242, 229,
					34, 157, 201, 218, 182, 27, 100, 23, 16, 249, 77, 204, 208,
					109, 239, 150, 159, 52, 35,
				],
				[
					220, 90, 147, 118, 107, 85, 9, 230, 88, 44, 135, 13, 26,
					178, 183, 21, 71, 108, 199, 105, 173, 231, 152, 107, 67,
					255, 229, 45, 177, 12, 194, 20,
				],
				[
					10, 215, 144, 113, 27, 224, 225, 209, 72, 165, 142, 44, 205,
					5, 105, 204, 119, 61, 2, 0, 243, 47, 78, 49, 32, 70, 38, 10,
					98, 125, 113, 16,
				],
				[
					13, 142, 136, 64, 125, 133, 138, 35, 81, 123, 20, 207, 224,
					185, 241, 206, 183, 239, 152, 46, 127, 251, 71, 145, 95,
					171, 194, 240, 160, 43, 176, 22,
				],
				[
					234, 137, 74, 200, 120, 19, 178, 233, 156, 250, 69, 79, 132,
					49, 227, 244, 71, 239, 133, 91, 202, 250, 9, 73, 254, 209,
					162, 235, 156, 248, 18, 11,
				],
				[
					15, 102, 125, 130, 224, 15, 225, 199, 176, 95, 103, 46, 221,
					193, 218, 76, 192, 181, 252, 209, 80, 241, 214, 8, 51, 146,
					174, 138, 23, 109, 111, 42,
				],
				[
					199, 30, 140, 12, 46, 251, 196, 160, 218, 92, 124, 215, 18,
					6, 175, 220, 144, 204, 209, 213, 62, 58, 105, 65, 111, 199,
					14, 53, 52, 22, 186, 22,
				],
				[
					127, 118, 245, 98, 121, 114, 241, 71, 196, 67, 22, 33, 170,
					135, 92, 194, 253, 139, 91, 191, 15, 166, 84, 64, 81, 107,
					197, 34, 0, 92, 152, 11,
				],
				[
					55, 223, 215, 171, 24, 57, 187, 55, 131, 188, 11, 83, 176,
					237, 112, 254, 170, 128, 44, 82, 71, 247, 59, 16, 231, 64,
					42, 237, 90, 126, 231, 16,
				],
				[
					53, 218, 203, 208, 135, 14, 14, 151, 20, 219, 132, 54, 24,
					111, 5, 77, 161, 111, 182, 203, 210, 174, 39, 178, 54, 216,
					0, 105, 142, 241, 154, 31,
				],
				[
					6, 125, 253, 216, 50, 17, 221, 20, 36, 90, 52, 163, 7, 24,
					29, 191, 205, 179, 73, 212, 93, 164, 200, 231, 170, 26, 81,
					3, 36, 47, 219, 31,
				],
				[
					235, 192, 166, 206, 182, 65, 3, 212, 147, 131, 6, 57, 203,
					147, 228, 93, 250, 117, 158, 222, 87, 215, 220, 96, 180,
					153, 77, 10, 117, 24, 27, 40,
				],
				[
					64, 225, 25, 231, 21, 126, 49, 158, 234, 68, 244, 2, 23, 30,
					9, 13, 124, 191, 92, 250, 151, 185, 172, 91, 101, 176, 39,
					71, 151, 149, 140, 9,
				],
				[
					36, 92, 133, 156, 238, 162, 76, 85, 74, 196, 247, 23, 183,
					8, 101, 78, 77, 26, 88, 64, 225, 192, 23, 100, 142, 195, 60,
					68, 233, 44, 92, 5,
				],
				[
					143, 15, 163, 247, 85, 65, 122, 143, 235, 59, 92, 11, 69,
					238, 44, 200, 185, 60, 161, 142, 9, 107, 162, 136, 187, 139,
					67, 236, 239, 15, 71, 17,
				],
			],
			[
				[
					195, 217, 39, 101, 144, 109, 223, 90, 162, 231, 16, 133, 58,
					66, 137, 244, 180, 50, 74, 190, 210, 29, 175, 143, 159, 148,
					252, 15, 24, 121, 54, 25,
				],
				[
					76, 165, 61, 160, 138, 252, 143, 234, 103, 199, 103, 48,
					199, 236, 161, 59, 67, 70, 0, 231, 195, 125, 28, 20, 197,
					154, 80, 136, 58, 208, 59, 4,
				],
				[
					131, 241, 209, 144, 53, 89, 108, 44, 203, 38, 93, 22, 157,
					127, 19, 80, 79, 169, 173, 250, 228, 12, 243, 184, 3, 126,
					43, 80, 157, 103, 93, 12,
				],
				[
					220, 42, 33, 158, 199, 246, 34, 165, 215, 92, 203, 91, 61,
					77, 212, 169, 198, 254, 208, 214, 195, 76, 11, 238, 77, 171,
					170, 205, 63, 171, 138, 24,
				],
				[
					20, 7, 248, 66, 100, 124, 63, 189, 209, 244, 135, 97, 153,
					91, 44, 56, 97, 225, 151, 2, 112, 171, 22, 245, 68, 117,
					143, 116, 173, 65, 224, 19,
				],
				[
					41, 209, 45, 217, 90, 120, 81, 221, 87, 18, 90, 238, 63, 32,
					94, 188, 19, 44, 183, 80, 42, 238, 160, 34, 112, 70, 119,
					12, 193, 7, 32, 18,
				],
				[
					97, 147, 97, 13, 251, 235, 124, 105, 113, 32, 123, 118, 232,
					79, 187, 141, 64, 124, 92, 12, 146, 104, 180, 187, 89, 50,
					179, 110, 56, 128, 28, 30,
				],
				[
					141, 248, 19, 132, 23, 209, 133, 10, 110, 103, 144, 39, 96,
					198, 63, 74, 175, 237, 90, 151, 33, 64, 114, 146, 138, 33,
					16, 220, 45, 186, 197, 46,
				],
				[
					166, 212, 105, 224, 131, 195, 172, 155, 85, 100, 81, 240,
					17, 201, 76, 236, 249, 252, 89, 53, 229, 175, 238, 92, 89,
					75, 241, 124, 192, 146, 150, 1,
				],
				[
					117, 124, 252, 188, 119, 239, 149, 188, 249, 68, 161, 199,
					15, 88, 252, 163, 218, 106, 191, 235, 121, 53, 20, 207, 203,
					203, 79, 108, 90, 65, 97, 20,
				],
				[
					31, 70, 127, 158, 130, 134, 58, 158, 51, 26, 181, 52, 147,
					219, 45, 4, 114, 179, 156, 22, 224, 250, 36, 66, 147, 126,
					79, 123, 51, 53, 109, 27,
				],
				[
					13, 203, 100, 109, 71, 213, 240, 69, 87, 169, 189, 100, 185,
					178, 207, 10, 244, 226, 162, 43, 105, 74, 84, 92, 221, 140,
					203, 195, 121, 138, 216, 4,
				],
				[
					83, 30, 75, 188, 171, 121, 84, 144, 205, 49, 121, 206, 163,
					11, 84, 39, 127, 7, 93, 238, 25, 191, 100, 87, 5, 114, 41,
					213, 127, 97, 42, 28,
				],
				[
					95, 85, 164, 250, 103, 171, 91, 243, 56, 24, 29, 50, 139,
					59, 189, 109, 36, 80, 70, 43, 3, 47, 220, 128, 29, 4, 127,
					108, 127, 123, 125, 34,
				],
				[
					100, 229, 112, 161, 140, 137, 28, 151, 123, 104, 240, 10,
					66, 240, 140, 0, 52, 32, 86, 241, 176, 181, 232, 224, 133,
					109, 204, 74, 219, 113, 189, 27,
				],
				[
					61, 79, 4, 3, 232, 130, 138, 174, 175, 250, 193, 145, 157,
					160, 243, 18, 127, 17, 92, 201, 132, 255, 188, 219, 241,
					162, 146, 181, 242, 17, 94, 21,
				],
				[
					59, 155, 34, 186, 167, 136, 137, 246, 162, 202, 100, 211,
					143, 254, 248, 203, 116, 14, 2, 102, 94, 179, 168, 205, 225,
					171, 55, 53, 27, 169, 49, 35,
				],
			],
			[
				[
					30, 57, 242, 178, 42, 233, 40, 219, 173, 165, 214, 248, 109,
					156, 209, 9, 239, 16, 12, 151, 78, 237, 136, 94, 69, 125,
					182, 173, 84, 246, 186, 35,
				],
				[
					166, 152, 141, 16, 46, 240, 193, 220, 161, 107, 6, 22, 5,
					35, 244, 30, 235, 43, 222, 245, 26, 247, 151, 186, 56, 35,
					174, 117, 200, 109, 51, 20,
				],
				[
					173, 215, 110, 30, 84, 55, 200, 109, 158, 200, 11, 177, 107,
					152, 65, 141, 133, 181, 248, 150, 240, 192, 193, 83, 210,
					154, 196, 57, 141, 247, 35, 38,
				],
				[
					94, 220, 120, 141, 183, 192, 53, 83, 177, 144, 119, 141, 59,
					37, 18, 245, 103, 172, 156, 111, 114, 90, 105, 70, 136, 174,
					37, 189, 9, 49, 167, 34,
				],
				[
					103, 30, 205, 214, 131, 30, 130, 181, 122, 216, 7, 142, 55,
					225, 128, 223, 60, 180, 24, 30, 3, 135, 102, 110, 117, 67,
					202, 156, 165, 165, 133, 34,
				],
				[
					16, 98, 194, 118, 72, 205, 122, 71, 135, 194, 229, 184, 82,
					86, 119, 213, 223, 228, 68, 6, 143, 63, 115, 78, 244, 119,
					114, 155, 14, 208, 67, 38,
				],
				[
					133, 188, 8, 89, 202, 104, 34, 59, 5, 61, 60, 221, 224, 79,
					113, 143, 70, 193, 10, 207, 21, 185, 157, 34, 189, 13, 231,
					188, 208, 132, 122, 45,
				],
				[
					170, 192, 189, 1, 167, 68, 104, 12, 66, 185, 44, 90, 50,
					193, 1, 139, 19, 1, 121, 182, 231, 20, 143, 114, 77, 203,
					170, 238, 36, 229, 3, 48,
				],
				[
					208, 34, 153, 69, 126, 72, 190, 97, 75, 206, 133, 55, 225,
					109, 11, 38, 115, 33, 51, 15, 138, 126, 28, 2, 149, 90, 88,
					27, 94, 97, 5, 30,
				],
				[
					137, 165, 118, 89, 132, 242, 156, 239, 137, 89, 12, 109,
					254, 145, 53, 37, 78, 72, 194, 151, 18, 114, 41, 83, 137,
					199, 155, 62, 150, 29, 211, 34,
				],
				[
					218, 217, 43, 158, 203, 129, 250, 82, 112, 81, 229, 122, 52,
					62, 76, 105, 17, 223, 20, 16, 59, 246, 194, 113, 98, 176,
					34, 63, 58, 34, 233, 1,
				],
				[
					6, 232, 127, 30, 57, 52, 233, 2, 126, 225, 251, 41, 174,
					167, 3, 35, 175, 199, 177, 184, 149, 96, 225, 126, 183, 1,
					234, 112, 51, 192, 32, 31,
				],
				[
					69, 51, 208, 239, 27, 236, 93, 80, 78, 43, 89, 132, 189,
					193, 204, 131, 145, 102, 70, 171, 200, 128, 134, 101, 127,
					181, 54, 224, 195, 72, 238, 17,
				],
				[
					168, 195, 122, 13, 20, 57, 175, 129, 177, 236, 123, 159,
					156, 84, 18, 233, 81, 41, 234, 67, 199, 135, 254, 79, 24, 3,
					35, 23, 21, 39, 39, 2,
				],
				[
					204, 125, 109, 146, 6, 18, 148, 33, 188, 133, 53, 186, 115,
					144, 2, 246, 226, 72, 16, 19, 206, 127, 41, 54, 154, 27, 21,
					164, 50, 165, 250, 2,
				],
				[
					54, 42, 168, 101, 248, 209, 39, 1, 49, 184, 139, 155, 62,
					210, 185, 243, 112, 150, 241, 147, 199, 189, 22, 71, 15,
					131, 42, 68, 30, 81, 191, 38,
				],
				[
					179, 247, 2, 8, 182, 2, 54, 66, 181, 6, 93, 244, 108, 185,
					166, 11, 115, 118, 224, 196, 150, 135, 235, 81, 5, 204, 187,
					252, 37, 140, 252, 37,
				],
			],
			[
				[
					194, 117, 1, 225, 41, 76, 229, 32, 27, 101, 121, 178, 174,
					103, 109, 107, 255, 67, 184, 7, 216, 71, 46, 192, 222, 252,
					172, 162, 176, 26, 132, 5,
				],
				[
					106, 9, 106, 6, 117, 148, 77, 34, 117, 59, 178, 246, 59,
					139, 56, 102, 51, 191, 29, 54, 132, 7, 204, 129, 136, 124,
					81, 24, 159, 73, 29, 4,
				],
				[
					23, 119, 2, 108, 251, 66, 214, 123, 163, 71, 40, 36, 82,
					128, 173, 145, 115, 38, 8, 80, 35, 134, 145, 116, 203, 16,
					193, 4, 215, 96, 14, 6,
				],
				[
					106, 4, 72, 126, 99, 140, 197, 186, 159, 35, 165, 15, 1, 85,
					187, 143, 129, 228, 151, 39, 248, 217, 53, 66, 56, 110, 170,
					213, 199, 6, 140, 42,
				],
				[
					116, 2, 7, 179, 218, 225, 138, 243, 241, 140, 151, 84, 215,
					158, 34, 193, 232, 96, 189, 91, 236, 97, 167, 179, 40, 119,
					176, 170, 185, 18, 50, 22,
				],
				[
					205, 140, 12, 9, 236, 137, 230, 237, 213, 248, 188, 209,
					171, 227, 93, 31, 163, 110, 97, 170, 218, 103, 91, 187, 77,
					176, 184, 194, 11, 164, 65, 33,
				],
				[
					171, 172, 134, 8, 67, 98, 105, 219, 19, 104, 150, 32, 111,
					35, 99, 201, 115, 147, 143, 24, 226, 87, 209, 196, 31, 100,
					3, 22, 10, 153, 175, 32,
				],
				[
					241, 35, 124, 182, 179, 19, 176, 169, 107, 233, 44, 101, 23,
					239, 90, 53, 28, 144, 52, 140, 108, 114, 114, 226, 46, 2,
					32, 121, 196, 232, 170, 3,
				],
				[
					171, 199, 42, 173, 170, 137, 52, 57, 88, 39, 91, 249, 158,
					246, 48, 170, 54, 135, 205, 27, 180, 239, 177, 171, 154, 75,
					97, 185, 147, 126, 231, 39,
				],
				[
					212, 96, 219, 52, 32, 207, 139, 91, 189, 186, 77, 244, 113,
					3, 245, 3, 95, 254, 39, 232, 102, 249, 210, 235, 50, 105,
					224, 176, 132, 85, 28, 15,
				],
				[
					16, 173, 172, 58, 126, 248, 79, 145, 245, 131, 129, 16, 175,
					9, 162, 197, 180, 199, 219, 41, 75, 203, 29, 235, 94, 181,
					87, 129, 4, 10, 220, 37,
				],
				[
					85, 185, 230, 97, 46, 45, 33, 185, 20, 29, 12, 51, 94, 184,
					20, 13, 136, 65, 204, 205, 118, 96, 233, 100, 10, 247, 35,
					149, 87, 119, 111, 29,
				],
				[
					13, 41, 38, 112, 136, 219, 227, 243, 163, 240, 204, 71, 61,
					177, 246, 242, 113, 158, 144, 29, 251, 50, 250, 230, 102,
					150, 163, 123, 169, 207, 23, 29,
				],
				[
					231, 187, 3, 236, 224, 61, 83, 68, 102, 159, 217, 105, 169,
					134, 62, 237, 9, 160, 229, 139, 248, 121, 81, 228, 30, 231,
					227, 53, 231, 56, 68, 39,
				],
				[
					19, 83, 70, 126, 123, 171, 220, 58, 161, 133, 31, 191, 133,
					246, 223, 204, 52, 165, 250, 192, 171, 247, 243, 138, 30,
					175, 70, 218, 97, 7, 92, 6,
				],
				[
					222, 186, 92, 231, 7, 28, 229, 79, 17, 112, 144, 189, 56,
					202, 210, 115, 182, 81, 224, 195, 16, 207, 221, 218, 106,
					110, 249, 198, 230, 91, 25, 39,
				],
				[
					132, 207, 222, 37, 253, 207, 107, 141, 100, 206, 212, 217,
					118, 65, 158, 111, 56, 40, 85, 255, 127, 102, 44, 3, 119,
					45, 132, 59, 118, 161, 3, 11,
				],
			],
			[
				[
					228, 33, 205, 164, 218, 248, 22, 92, 186, 45, 172, 124, 175,
					240, 10, 87, 237, 223, 186, 241, 189, 183, 120, 76, 250, 97,
					187, 132, 219, 232, 38, 37,
				],
				[
					179, 139, 187, 59, 132, 17, 146, 249, 14, 178, 128, 19, 55,
					97, 66, 20, 231, 43, 74, 99, 82, 230, 149, 2, 49, 108, 177,
					218, 234, 49, 142, 32,
				],
				[
					252, 23, 157, 216, 35, 10, 239, 237, 178, 13, 165, 110, 54,
					57, 152, 15, 119, 189, 68, 186, 96, 82, 68, 243, 47, 28, 85,
					108, 128, 171, 206, 6,
				],
				[
					33, 159, 74, 154, 49, 60, 109, 224, 232, 225, 31, 189, 205,
					68, 146, 56, 228, 19, 127, 83, 226, 49, 39, 93, 232, 231,
					109, 243, 62, 150, 211, 18,
				],
				[
					142, 68, 241, 183, 57, 147, 103, 73, 69, 114, 83, 153, 219,
					195, 6, 212, 255, 210, 158, 5, 206, 157, 135, 96, 11, 233,
					126, 227, 139, 146, 162, 36,
				],
				[
					51, 226, 201, 248, 193, 181, 102, 196, 73, 154, 0, 173, 247,
					77, 164, 190, 28, 178, 56, 252, 55, 1, 110, 14, 227, 9, 131,
					62, 83, 85, 175, 37,
				],
				[
					131, 75, 3, 147, 168, 205, 209, 186, 244, 9, 251, 174, 13,
					166, 204, 86, 222, 219, 193, 250, 187, 52, 29, 96, 2, 170,
					13, 203, 180, 144, 184, 18,
				],
				[
					53, 195, 240, 223, 6, 225, 73, 82, 103, 233, 138, 41, 5,
					196, 136, 221, 134, 49, 195, 241, 50, 171, 96, 149, 71, 202,
					1, 175, 26, 135, 114, 12,
				],
				[
					35, 209, 87, 145, 113, 67, 43, 48, 204, 245, 32, 66, 52,
					157, 19, 234, 67, 208, 145, 79, 14, 194, 184, 253, 243, 81,
					186, 157, 222, 70, 66, 26,
				],
				[
					7, 161, 67, 76, 228, 3, 172, 35, 6, 217, 120, 97, 233, 159,
					125, 107, 234, 164, 209, 90, 207, 182, 44, 221, 187, 194,
					101, 89, 41, 65, 201, 19,
				],
				[
					248, 83, 233, 18, 205, 142, 151, 18, 173, 91, 100, 197, 27,
					77, 224, 247, 177, 146, 247, 17, 92, 79, 223, 59, 72, 169,
					66, 46, 176, 152, 20, 36,
				],
				[
					214, 88, 195, 69, 203, 127, 45, 110, 33, 205, 232, 118, 108,
					4, 102, 121, 123, 112, 66, 110, 153, 128, 206, 234, 224,
					100, 84, 234, 215, 159, 159, 24,
				],
				[
					188, 169, 26, 249, 94, 253, 23, 29, 23, 37, 165, 41, 175,
					139, 45, 57, 100, 254, 203, 142, 18, 78, 26, 206, 79, 250,
					111, 213, 58, 83, 83, 13,
				],
				[
					242, 182, 250, 224, 12, 66, 179, 248, 127, 89, 227, 111,
					143, 78, 57, 224, 123, 234, 14, 10, 133, 36, 216, 33, 25,
					84, 118, 83, 230, 24, 215, 13,
				],
				[
					65, 215, 123, 113, 8, 43, 61, 107, 90, 40, 43, 169, 28, 238,
					94, 118, 43, 242, 213, 96, 187, 237, 154, 120, 144, 253,
					237, 145, 87, 227, 48, 38,
				],
				[
					201, 206, 185, 239, 8, 51, 198, 80, 236, 52, 108, 241, 168,
					164, 29, 13, 5, 202, 109, 19, 205, 176, 221, 63, 48, 69,
					145, 111, 250, 66, 206, 33,
				],
				[
					66, 208, 240, 14, 240, 168, 145, 67, 64, 60, 126, 196, 190,
					121, 105, 236, 245, 106, 28, 110, 251, 56, 154, 9, 116, 101,
					106, 68, 87, 235, 174, 2,
				],
			],
			[
				[
					131, 152, 156, 118, 214, 132, 30, 72, 105, 124, 246, 109, 3,
					8, 17, 246, 216, 131, 15, 82, 35, 201, 41, 178, 197, 104,
					134, 27, 251, 45, 218, 29,
				],
				[
					191, 127, 24, 88, 194, 26, 115, 117, 12, 194, 17, 102, 7,
					125, 239, 18, 187, 220, 47, 35, 135, 109, 168, 61, 50, 30,
					201, 236, 92, 94, 66, 29,
				],
				[
					243, 166, 40, 70, 120, 53, 55, 197, 44, 47, 86, 213, 50, 19,
					150, 178, 205, 72, 199, 47, 209, 175, 104, 115, 58, 199,
					193, 228, 58, 155, 6, 7,
				],
				[
					38, 107, 10, 118, 157, 65, 134, 31, 66, 48, 103, 170, 151,
					201, 13, 126, 149, 153, 83, 117, 53, 146, 81, 47, 141, 229,
					101, 224, 2, 181, 71, 39,
				],
				[
					133, 135, 169, 232, 122, 30, 11, 86, 195, 214, 138, 148,
					246, 117, 87, 186, 61, 181, 223, 7, 138, 139, 238, 175, 82,
					54, 121, 135, 201, 169, 18, 31,
				],
				[
					244, 54, 34, 207, 107, 170, 49, 102, 67, 14, 208, 89, 72,
					182, 165, 1, 232, 138, 236, 198, 157, 213, 179, 179, 208,
					109, 113, 49, 98, 123, 1, 37,
				],
				[
					253, 226, 4, 241, 206, 221, 33, 217, 100, 127, 138, 30, 96,
					230, 177, 226, 197, 255, 150, 83, 140, 2, 238, 79, 65, 7,
					121, 13, 21, 90, 168, 27,
				],
				[
					172, 200, 99, 58, 136, 81, 131, 70, 86, 217, 230, 64, 178,
					94, 1, 248, 189, 150, 226, 151, 207, 185, 146, 102, 62, 137,
					41, 203, 130, 114, 107, 0,
				],
				[
					6, 148, 21, 194, 95, 49, 29, 233, 228, 62, 136, 13, 22, 175,
					253, 220, 202, 95, 31, 179, 29, 126, 16, 139, 189, 49, 145,
					27, 18, 205, 78, 32,
				],
				[
					144, 113, 167, 54, 244, 133, 63, 156, 74, 3, 100, 104, 49,
					238, 175, 133, 191, 144, 185, 132, 166, 55, 119, 70, 199,
					211, 183, 143, 196, 62, 211, 18,
				],
				[
					44, 140, 121, 85, 73, 19, 10, 134, 4, 68, 81, 111, 22, 28,
					244, 26, 9, 165, 1, 185, 234, 148, 35, 117, 101, 19, 28,
					205, 200, 62, 146, 10,
				],
				[
					149, 74, 163, 155, 186, 52, 124, 22, 223, 156, 102, 215, 21,
					3, 232, 146, 195, 174, 167, 18, 175, 229, 106, 51, 129, 214,
					176, 239, 198, 100, 109, 21,
				],
				[
					116, 183, 37, 71, 211, 160, 205, 14, 161, 6, 233, 236, 215,
					214, 217, 139, 66, 17, 118, 116, 111, 43, 157, 244, 26, 193,
					144, 46, 49, 147, 149, 34,
				],
				[
					63, 193, 133, 54, 114, 222, 238, 252, 56, 173, 112, 9, 205,
					89, 156, 215, 118, 253, 65, 146, 194, 28, 222, 162, 8, 108,
					106, 174, 86, 198, 136, 19,
				],
				[
					44, 169, 58, 127, 51, 115, 203, 56, 116, 251, 114, 179, 123,
					228, 231, 128, 4, 74, 123, 74, 17, 61, 134, 155, 107, 254,
					186, 147, 27, 29, 166, 34,
				],
				[
					65, 39, 189, 25, 180, 130, 139, 89, 254, 122, 79, 156, 102,
					150, 190, 65, 252, 240, 218, 72, 73, 146, 249, 171, 68, 79,
					83, 131, 112, 204, 140, 34,
				],
				[
					177, 180, 25, 41, 233, 99, 197, 228, 99, 65, 246, 222, 213,
					61, 44, 168, 160, 0, 203, 99, 150, 201, 122, 2, 102, 188,
					14, 4, 90, 204, 146, 46,
				],
			],
			[
				[
					161, 189, 77, 62, 114, 247, 228, 197, 191, 228, 165, 104,
					182, 104, 221, 62, 200, 100, 5, 192, 60, 193, 137, 57, 191,
					72, 43, 143, 111, 169, 17, 17,
				],
				[
					245, 85, 149, 229, 57, 242, 137, 114, 65, 16, 20, 79, 214,
					126, 234, 66, 211, 129, 36, 169, 187, 16, 64, 212, 244, 177,
					137, 147, 17, 83, 133, 15,
				],
				[
					178, 153, 53, 200, 134, 225, 40, 221, 180, 138, 175, 137,
					44, 104, 201, 242, 230, 45, 211, 195, 225, 98, 234, 35, 45,
					167, 138, 95, 212, 158, 120, 19,
				],
				[
					223, 166, 225, 64, 137, 96, 98, 117, 232, 168, 186, 40, 146,
					24, 17, 145, 139, 91, 115, 23, 112, 110, 36, 83, 212, 142,
					98, 34, 223, 66, 249, 16,
				],
				[
					244, 104, 112, 131, 210, 25, 27, 91, 171, 104, 27, 30, 244,
					8, 47, 0, 165, 55, 208, 125, 47, 81, 177, 173, 97, 227, 192,
					3, 108, 125, 213, 33,
				],
				[
					160, 116, 87, 247, 163, 33, 125, 192, 185, 46, 23, 66, 37,
					139, 222, 38, 127, 149, 234, 149, 83, 210, 194, 129, 229, 7,
					103, 21, 96, 137, 193, 19,
				],
				[
					210, 220, 218, 191, 118, 2, 233, 209, 56, 73, 39, 28, 177,
					108, 240, 75, 194, 228, 237, 155, 39, 11, 92, 235, 195, 147,
					98, 130, 120, 22, 22, 47,
				],
				[
					14, 27, 164, 222, 6, 229, 160, 170, 11, 47, 136, 50, 63,
					136, 36, 130, 2, 111, 34, 34, 190, 189, 221, 51, 212, 248,
					108, 25, 79, 98, 54, 43,
				],
				[
					137, 179, 248, 203, 47, 62, 5, 17, 28, 22, 210, 35, 167,
					131, 251, 178, 141, 134, 115, 7, 23, 122, 190, 106, 49, 78,
					106, 45, 81, 241, 110, 1,
				],
				[
					127, 153, 166, 152, 137, 84, 179, 114, 223, 100, 123, 89,
					219, 193, 161, 52, 215, 192, 133, 157, 24, 177, 135, 25, 1,
					175, 137, 44, 40, 79, 142, 24,
				],
				[
					142, 189, 168, 134, 155, 22, 21, 14, 50, 23, 211, 151, 58,
					89, 204, 108, 38, 115, 54, 255, 164, 166, 110, 122, 40, 248,
					124, 36, 243, 221, 227, 23,
				],
				[
					131, 159, 210, 51, 204, 120, 26, 103, 100, 220, 209, 13,
					128, 170, 101, 241, 9, 249, 196, 26, 10, 61, 227, 113, 207,
					47, 74, 27, 83, 251, 128, 28,
				],
				[
					140, 175, 143, 186, 185, 192, 3, 89, 110, 103, 202, 240, 5,
					190, 207, 127, 148, 137, 121, 41, 90, 118, 93, 74, 229, 69,
					80, 247, 42, 122, 52, 43,
				],
				[
					196, 248, 60, 255, 189, 237, 207, 177, 208, 254, 107, 46,
					26, 69, 60, 203, 13, 197, 132, 223, 131, 230, 11, 34, 144,
					98, 222, 41, 23, 18, 103, 0,
				],
				[
					137, 138, 139, 87, 51, 107, 145, 240, 118, 108, 89, 199,
					145, 28, 213, 186, 176, 210, 43, 12, 151, 79, 107, 116, 193,
					55, 143, 170, 209, 123, 82, 47,
				],
				[
					240, 209, 187, 105, 128, 23, 152, 148, 9, 83, 156, 67, 179,
					196, 59, 16, 103, 253, 161, 187, 156, 141, 165, 23, 100,
					134, 116, 222, 49, 56, 92, 39,
				],
				[
					55, 4, 244, 78, 43, 67, 1, 226, 125, 146, 224, 254, 37, 224,
					20, 80, 64, 105, 110, 254, 243, 2, 84, 125, 92, 37, 90, 206,
					248, 89, 7, 26,
				],
			],
			[
				[
					187, 144, 217, 31, 226, 131, 86, 135, 103, 34, 217, 29, 252,
					218, 188, 113, 113, 16, 216, 238, 5, 57, 54, 206, 178, 167,
					138, 240, 105, 227, 220, 46,
				],
				[
					189, 132, 143, 24, 15, 38, 49, 29, 159, 21, 91, 185, 9, 82,
					210, 90, 151, 245, 216, 252, 136, 88, 136, 208, 141, 253,
					122, 30, 112, 242, 150, 8,
				],
				[
					138, 10, 143, 98, 18, 95, 225, 230, 191, 26, 19, 112, 218,
					31, 15, 8, 84, 228, 239, 224, 147, 241, 61, 135, 57, 40,
					198, 86, 148, 184, 138, 22,
				],
				[
					197, 83, 40, 53, 71, 16, 6, 103, 42, 60, 101, 116, 151, 95,
					26, 59, 132, 138, 166, 60, 252, 65, 208, 184, 245, 244, 254,
					172, 144, 191, 210, 39,
				],
				[
					218, 245, 131, 17, 163, 233, 243, 70, 83, 197, 44, 28, 137,
					47, 108, 233, 198, 223, 6, 154, 143, 162, 209, 123, 205,
					231, 147, 3, 232, 39, 237, 22,
				],
				[
					26, 169, 89, 132, 135, 1, 85, 204, 242, 141, 42, 248, 101,
					135, 35, 148, 74, 226, 198, 148, 197, 112, 34, 110, 212,
					203, 87, 179, 133, 41, 199, 46,
				],
				[
					161, 43, 10, 34, 208, 55, 167, 54, 119, 82, 68, 215, 221,
					179, 183, 163, 249, 27, 51, 166, 169, 153, 236, 90, 174,
					111, 104, 82, 140, 94, 3, 1,
				],
				[
					125, 179, 212, 104, 161, 49, 125, 199, 194, 152, 134, 166,
					140, 77, 169, 104, 120, 153, 225, 70, 168, 222, 13, 130,
					194, 158, 251, 239, 215, 41, 242, 30,
				],
				[
					249, 143, 177, 164, 49, 164, 122, 202, 243, 192, 190, 122,
					219, 39, 23, 73, 76, 137, 222, 125, 175, 197, 125, 153, 90,
					2, 133, 213, 103, 102, 203, 27,
				],
				[
					128, 34, 33, 58, 16, 99, 228, 208, 36, 161, 121, 216, 116,
					175, 250, 9, 42, 24, 148, 100, 21, 176, 80, 84, 111, 237,
					166, 54, 183, 133, 138, 23,
				],
				[
					63, 232, 228, 116, 50, 157, 213, 248, 33, 232, 247, 24, 69,
					232, 22, 211, 205, 122, 87, 106, 13, 71, 119, 83, 226, 110,
					18, 193, 221, 213, 109, 33,
				],
				[
					76, 211, 9, 76, 105, 155, 174, 9, 212, 168, 116, 47, 57, 48,
					85, 149, 70, 214, 197, 249, 112, 72, 162, 208, 36, 239, 200,
					63, 169, 156, 49, 28,
				],
				[
					64, 43, 35, 0, 248, 209, 205, 2, 32, 169, 116, 78, 8, 47,
					168, 178, 244, 187, 198, 6, 206, 245, 241, 166, 127, 57, 54,
					137, 74, 43, 66, 0,
				],
				[
					128, 28, 98, 186, 16, 68, 190, 75, 49, 213, 33, 63, 68, 196,
					178, 189, 123, 137, 17, 254, 245, 53, 200, 5, 58, 133, 130,
					78, 70, 55, 16, 3,
				],
				[
					40, 61, 124, 174, 231, 227, 124, 224, 136, 246, 216, 45, 2,
					160, 68, 137, 75, 105, 159, 252, 189, 157, 75, 12, 15, 39,
					160, 187, 104, 141, 146, 39,
				],
				[
					25, 246, 12, 206, 159, 197, 95, 78, 40, 223, 41, 197, 169,
					185, 100, 224, 162, 131, 50, 204, 29, 59, 254, 155, 163, 22,
					20, 146, 218, 254, 113, 35,
				],
				[
					2, 250, 217, 60, 162, 5, 234, 212, 178, 28, 157, 20, 254,
					214, 88, 194, 159, 187, 132, 74, 29, 118, 88, 92, 246, 239,
					212, 20, 24, 146, 148, 0,
				],
			],
			[
				[
					195, 97, 5, 16, 219, 98, 57, 167, 53, 90, 13, 65, 152, 142,
					18, 70, 223, 64, 195, 229, 224, 155, 114, 205, 63, 96, 149,
					124, 76, 4, 251, 27,
				],
				[
					176, 160, 19, 129, 14, 141, 175, 116, 128, 52, 232, 182,
					173, 55, 20, 168, 244, 32, 204, 25, 245, 191, 39, 34, 95,
					222, 27, 223, 138, 35, 254, 46,
				],
				[
					197, 165, 141, 247, 23, 87, 181, 104, 166, 139, 55, 86, 113,
					154, 52, 14, 118, 15, 180, 115, 94, 95, 168, 244, 163, 152,
					254, 63, 188, 219, 230, 40,
				],
				[
					101, 115, 42, 251, 148, 17, 101, 66, 232, 31, 100, 170, 116,
					14, 209, 175, 115, 98, 251, 154, 185, 242, 10, 222, 6, 3,
					74, 101, 106, 18, 56, 43,
				],
				[
					193, 102, 149, 86, 119, 50, 125, 206, 16, 66, 183, 57, 183,
					178, 129, 206, 247, 221, 102, 233, 229, 19, 107, 229, 179,
					95, 223, 64, 198, 86, 14, 43,
				],
				[
					19, 99, 205, 170, 177, 15, 213, 230, 139, 230, 120, 49, 13,
					222, 201, 178, 77, 34, 140, 46, 82, 120, 134, 159, 143, 161,
					8, 170, 111, 219, 244, 42,
				],
				[
					212, 211, 236, 37, 162, 104, 4, 153, 211, 195, 121, 178,
					179, 197, 70, 98, 108, 167, 59, 127, 201, 181, 233, 223,
					211, 142, 218, 161, 155, 137, 183, 37,
				],
				[
					55, 60, 211, 205, 95, 65, 111, 81, 150, 10, 183, 252, 65,
					59, 46, 78, 101, 142, 158, 165, 70, 129, 253, 204, 237, 187,
					103, 42, 18, 184, 170, 7,
				],
				[
					227, 43, 119, 127, 102, 160, 254, 226, 62, 234, 73, 168,
					234, 169, 29, 32, 92, 147, 176, 130, 19, 199, 164, 26, 50,
					174, 10, 191, 9, 184, 23, 37,
				],
				[
					239, 215, 73, 227, 98, 20, 237, 153, 170, 207, 122, 24, 183,
					168, 122, 183, 14, 190, 145, 8, 132, 152, 170, 225, 38, 215,
					91, 48, 45, 237, 173, 23,
				],
				[
					4, 50, 66, 87, 23, 151, 61, 77, 217, 172, 215, 172, 221, 29,
					190, 145, 149, 166, 65, 122, 179, 76, 64, 48, 222, 94, 1,
					211, 114, 223, 99, 42,
				],
				[
					74, 144, 239, 154, 41, 11, 56, 246, 12, 121, 199, 70, 55,
					134, 76, 134, 149, 79, 191, 28, 22, 199, 131, 169, 37, 205,
					24, 114, 247, 94, 119, 24,
				],
				[
					38, 68, 142, 113, 105, 42, 246, 193, 92, 69, 151, 21, 175,
					146, 108, 84, 97, 206, 89, 174, 167, 43, 172, 58, 233, 253,
					3, 55, 239, 61, 152, 7,
				],
				[
					64, 139, 88, 83, 190, 77, 213, 207, 102, 209, 189, 36, 110,
					178, 213, 32, 2, 74, 165, 227, 52, 190, 192, 87, 69, 57, 25,
					138, 187, 127, 157, 12,
				],
				[
					218, 116, 231, 243, 137, 143, 28, 145, 48, 211, 112, 197,
					88, 182, 209, 195, 46, 126, 9, 235, 42, 66, 193, 136, 225,
					237, 55, 179, 143, 203, 158, 6,
				],
				[
					86, 98, 233, 15, 95, 134, 61, 178, 61, 91, 85, 102, 121,
					118, 49, 228, 199, 40, 222, 164, 12, 228, 238, 35, 239, 103,
					184, 144, 240, 68, 212, 39,
				],
				[
					216, 101, 179, 60, 248, 8, 247, 227, 82, 211, 65, 233, 97,
					5, 176, 230, 203, 251, 246, 229, 78, 26, 76, 46, 108, 252,
					184, 63, 56, 36, 59, 35,
				],
			],
			[
				[
					25, 185, 71, 30, 213, 42, 230, 119, 51, 55, 217, 118, 129,
					250, 26, 87, 149, 89, 96, 217, 142, 125, 173, 68, 30, 79,
					212, 218, 43, 123, 66, 41,
				],
				[
					230, 13, 236, 208, 35, 5, 0, 167, 64, 199, 211, 250, 43,
					104, 38, 158, 98, 113, 145, 65, 166, 208, 208, 193, 68, 124,
					207, 161, 13, 199, 98, 10,
				],
				[
					193, 149, 240, 205, 95, 150, 230, 126, 219, 118, 249, 133,
					47, 75, 227, 224, 45, 88, 222, 233, 227, 243, 239, 251, 238,
					133, 195, 205, 136, 217, 36, 29,
				],
				[
					74, 227, 84, 5, 38, 19, 98, 61, 193, 97, 182, 84, 139, 226,
					7, 214, 142, 63, 57, 54, 144, 172, 67, 154, 252, 162, 146,
					219, 120, 162, 108, 12,
				],
				[
					17, 113, 248, 215, 131, 160, 84, 92, 255, 8, 238, 205, 138,
					21, 136, 226, 66, 2, 244, 179, 190, 8, 137, 103, 174, 166,
					44, 232, 245, 201, 218, 38,
				],
				[
					247, 136, 203, 78, 14, 190, 244, 6, 189, 251, 95, 209, 66,
					90, 87, 79, 55, 27, 164, 228, 253, 118, 219, 191, 96, 56,
					53, 148, 231, 213, 254, 37,
				],
				[
					152, 90, 213, 209, 234, 191, 34, 216, 211, 153, 219, 197,
					80, 22, 162, 170, 232, 167, 93, 129, 78, 41, 240, 111, 84,
					126, 163, 8, 28, 69, 247, 20,
				],
				[
					220, 36, 73, 41, 6, 125, 26, 152, 107, 144, 113, 68, 92, 63,
					104, 59, 69, 160, 205, 197, 15, 42, 224, 142, 152, 63, 12,
					239, 157, 211, 230, 9,
				],
				[
					188, 154, 255, 76, 34, 254, 147, 79, 241, 221, 29, 192, 201,
					180, 90, 21, 9, 214, 34, 34, 77, 14, 240, 235, 137, 193, 91,
					164, 45, 196, 113, 7,
				],
				[
					16, 167, 239, 107, 58, 116, 214, 21, 127, 144, 179, 64, 199,
					218, 15, 113, 145, 103, 80, 51, 240, 218, 200, 119, 229,
					165, 238, 25, 14, 238, 193, 10,
				],
				[
					136, 9, 232, 53, 109, 99, 166, 195, 165, 166, 48, 2, 104,
					206, 153, 148, 64, 69, 170, 223, 191, 65, 130, 181, 103,
					122, 45, 84, 226, 148, 199, 22,
				],
				[
					167, 57, 183, 94, 206, 44, 67, 67, 73, 96, 53, 85, 44, 71,
					2, 208, 53, 204, 42, 237, 155, 99, 194, 51, 108, 193, 15,
					75, 225, 133, 151, 14,
				],
				[
					44, 230, 186, 133, 82, 156, 170, 188, 164, 241, 104, 254,
					162, 255, 47, 182, 94, 239, 239, 126, 101, 141, 105, 202,
					245, 3, 147, 235, 214, 75, 171, 43,
				],
				[
					156, 14, 233, 233, 231, 44, 51, 246, 134, 223, 93, 0, 74,
					240, 115, 225, 250, 143, 131, 9, 227, 196, 26, 215, 242,
					233, 95, 75, 250, 228, 112, 22,
				],
				[
					193, 154, 235, 112, 174, 147, 45, 138, 177, 165, 82, 180,
					121, 167, 95, 173, 105, 200, 24, 24, 210, 215, 149, 44, 199,
					42, 49, 55, 98, 143, 98, 25,
				],
				[
					21, 176, 251, 228, 76, 105, 132, 204, 59, 159, 213, 6, 202,
					200, 8, 74, 254, 60, 169, 6, 162, 91, 118, 69, 46, 40, 71,
					39, 230, 198, 244, 11,
				],
				[
					251, 90, 83, 27, 146, 164, 22, 222, 207, 71, 105, 114, 181,
					11, 0, 5, 20, 212, 90, 223, 162, 236, 111, 56, 57, 80, 167,
					175, 236, 226, 83, 34,
				],
			],
			[
				[
					201, 163, 217, 148, 125, 189, 26, 240, 134, 240, 213, 134,
					84, 201, 251, 194, 246, 68, 155, 239, 83, 101, 253, 157, 19,
					151, 53, 67, 203, 39, 183, 40,
				],
				[
					109, 170, 28, 185, 60, 22, 185, 103, 74, 43, 84, 12, 65,
					107, 180, 207, 167, 114, 224, 233, 181, 254, 79, 137, 95,
					239, 48, 223, 140, 174, 51, 1,
				],
				[
					67, 132, 88, 157, 173, 247, 18, 251, 60, 113, 205, 32, 140,
					112, 154, 231, 246, 124, 50, 192, 49, 31, 51, 231, 174, 161,
					229, 69, 141, 35, 149, 39,
				],
				[
					85, 169, 235, 113, 249, 144, 161, 124, 105, 18, 20, 68, 39,
					72, 192, 202, 55, 19, 145, 237, 42, 163, 122, 42, 65, 44, 8,
					254, 222, 172, 92, 22,
				],
				[
					41, 67, 183, 183, 38, 196, 165, 219, 118, 192, 169, 185,
					243, 231, 244, 119, 237, 210, 197, 127, 114, 248, 126, 23,
					32, 55, 192, 135, 170, 136, 144, 16,
				],
				[
					31, 93, 163, 53, 206, 127, 68, 153, 93, 103, 172, 227, 85,
					1, 89, 110, 137, 165, 92, 158, 177, 222, 164, 54, 18, 54,
					248, 168, 106, 253, 251, 19,
				],
				[
					88, 40, 156, 220, 28, 238, 121, 71, 177, 17, 33, 192, 238,
					177, 176, 102, 128, 160, 125, 152, 234, 172, 13, 112, 200,
					238, 61, 147, 88, 202, 167, 40,
				],
				[
					48, 65, 108, 126, 162, 231, 203, 105, 230, 219, 27, 192, 96,
					194, 125, 201, 71, 71, 162, 180, 216, 215, 120, 176, 116,
					154, 141, 54, 249, 221, 222, 14,
				],
				[
					253, 194, 13, 7, 174, 88, 207, 56, 44, 135, 77, 30, 134,
					232, 198, 3, 138, 152, 190, 58, 159, 194, 33, 180, 239, 192,
					183, 47, 124, 103, 98, 30,
				],
				[
					184, 243, 106, 200, 29, 13, 133, 65, 113, 16, 41, 21, 124,
					155, 190, 202, 90, 241, 202, 91, 114, 183, 86, 161, 144, 8,
					103, 238, 234, 151, 152, 17,
				],
				[
					91, 101, 166, 218, 8, 197, 153, 248, 208, 48, 86, 30, 11,
					36, 229, 240, 203, 230, 213, 81, 173, 139, 197, 67, 208,
					143, 50, 204, 221, 210, 208, 14,
				],
				[
					35, 174, 136, 96, 169, 235, 135, 190, 193, 13, 45, 119, 220,
					189, 25, 173, 41, 72, 180, 8, 52, 116, 174, 19, 251, 246,
					37, 248, 79, 56, 176, 34,
				],
				[
					67, 69, 104, 111, 166, 23, 131, 22, 191, 105, 213, 190, 123,
					182, 176, 75, 92, 37, 214, 162, 106, 198, 189, 44, 149, 247,
					87, 218, 23, 83, 177, 12,
				],
				[
					191, 112, 213, 43, 152, 156, 208, 14, 169, 208, 191, 10,
					156, 197, 250, 56, 156, 53, 130, 151, 197, 131, 211, 160,
					65, 64, 173, 85, 210, 34, 164, 23,
				],
				[
					254, 217, 60, 253, 11, 115, 17, 218, 177, 9, 40, 33, 94, 24,
					216, 45, 103, 100, 19, 65, 76, 229, 25, 116, 120, 78, 71,
					156, 67, 204, 219, 33,
				],
				[
					48, 45, 31, 56, 215, 149, 81, 251, 164, 244, 246, 40, 233,
					159, 173, 123, 222, 127, 232, 81, 33, 161, 82, 197, 171, 78,
					41, 239, 142, 98, 215, 8,
				],
				[
					125, 187, 217, 165, 89, 154, 155, 98, 61, 73, 49, 80, 3,
					100, 43, 143, 159, 5, 203, 219, 233, 229, 58, 13, 141, 46,
					42, 202, 116, 65, 139, 24,
				],
			],
			[
				[
					17, 183, 205, 68, 170, 102, 252, 3, 214, 110, 142, 77, 50,
					140, 162, 229, 172, 148, 73, 69, 63, 115, 210, 135, 111,
					253, 195, 70, 66, 30, 143, 12,
				],
				[
					228, 114, 153, 26, 204, 190, 183, 156, 34, 207, 102, 132,
					146, 245, 70, 132, 67, 112, 132, 163, 97, 103, 132, 249,
					132, 104, 159, 140, 184, 72, 3, 47,
				],
				[
					170, 24, 28, 140, 249, 55, 179, 167, 93, 186, 168, 109, 103,
					122, 161, 127, 206, 90, 101, 70, 138, 23, 64, 160, 166, 105,
					146, 247, 221, 222, 122, 13,
				],
				[
					144, 65, 149, 46, 41, 145, 224, 83, 92, 246, 201, 170, 3,
					78, 247, 201, 221, 100, 209, 149, 120, 249, 159, 155, 155,
					136, 187, 86, 129, 132, 66, 15,
				],
				[
					124, 139, 132, 183, 14, 167, 92, 99, 166, 114, 17, 135, 158,
					235, 247, 149, 97, 113, 121, 99, 91, 217, 115, 203, 213, 72,
					117, 245, 100, 120, 92, 17,
				],
				[
					27, 82, 145, 218, 8, 1, 116, 22, 216, 64, 196, 1, 54, 12,
					182, 155, 67, 3, 198, 58, 110, 251, 175, 151, 223, 255, 62,
					183, 75, 53, 115, 41,
				],
				[
					181, 85, 239, 82, 22, 213, 207, 113, 249, 136, 222, 126,
					120, 182, 52, 78, 248, 55, 83, 200, 135, 248, 109, 44, 38,
					46, 140, 132, 35, 1, 231, 33,
				],
				[
					18, 44, 255, 192, 71, 140, 45, 81, 100, 151, 211, 57, 151,
					127, 182, 15, 166, 32, 114, 5, 140, 17, 161, 121, 157, 168,
					61, 99, 225, 14, 135, 12,
				],
				[
					185, 120, 62, 4, 249, 35, 106, 134, 0, 10, 177, 217, 167,
					229, 227, 218, 153, 144, 242, 158, 118, 170, 243, 50, 245,
					156, 48, 167, 204, 139, 189, 28,
				],
				[
					25, 81, 173, 166, 137, 202, 213, 171, 223, 224, 23, 104, 47,
					37, 247, 249, 83, 77, 4, 68, 13, 225, 61, 209, 38, 90, 143,
					189, 223, 156, 222, 31,
				],
				[
					122, 55, 87, 102, 13, 53, 230, 130, 46, 8, 68, 19, 214, 143,
					175, 87, 70, 2, 176, 186, 247, 174, 133, 18, 104, 213, 252,
					200, 86, 121, 239, 2,
				],
				[
					193, 152, 45, 225, 78, 5, 13, 151, 240, 115, 127, 88, 243,
					228, 216, 101, 25, 77, 91, 141, 233, 174, 164, 167, 147,
					233, 7, 27, 55, 124, 172, 8,
				],
				[
					73, 246, 47, 174, 191, 142, 67, 76, 132, 176, 251, 22, 241,
					6, 26, 183, 47, 77, 48, 247, 80, 47, 167, 112, 157, 70, 156,
					248, 196, 173, 100, 14,
				],
				[
					26, 160, 187, 0, 153, 25, 251, 44, 64, 116, 34, 83, 166, 39,
					255, 90, 228, 9, 215, 11, 41, 254, 179, 134, 121, 124, 185,
					254, 205, 205, 173, 30,
				],
				[
					7, 212, 201, 147, 161, 14, 21, 133, 45, 12, 50, 41, 222, 40,
					198, 156, 80, 84, 241, 253, 178, 252, 28, 236, 22, 221, 92,
					188, 23, 60, 217, 40,
				],
				[
					64, 31, 177, 48, 173, 205, 185, 181, 18, 173, 186, 30, 80,
					105, 113, 45, 127, 155, 255, 191, 12, 123, 154, 164, 89,
					144, 196, 203, 37, 80, 190, 13,
				],
				[
					197, 72, 152, 150, 169, 184, 79, 187, 27, 226, 112, 43, 192,
					74, 2, 249, 213, 159, 39, 75, 186, 141, 56, 150, 120, 216,
					13, 171, 43, 40, 230, 18,
				],
			],
		],
		sparseMatrices: [
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						76, 88, 8, 207, 141, 250, 214, 174, 15, 200, 11, 88,
						179, 0, 36, 232, 57, 65, 201, 69, 76, 211, 59, 107, 95,
						13, 131, 3, 1, 51, 53, 14,
					],
					[
						134, 14, 5, 181, 105, 153, 41, 111, 93, 74, 82, 227,
						145, 40, 91, 118, 75, 224, 121, 216, 91, 57, 38, 79, 53,
						121, 81, 221, 2, 179, 168, 25,
					],
					[
						132, 90, 98, 97, 46, 161, 65, 234, 201, 132, 43, 230,
						239, 40, 253, 192, 161, 218, 175, 249, 249, 14, 114, 32,
						57, 94, 7, 73, 96, 37, 216, 40,
					],
					[
						183, 175, 75, 24, 32, 143, 193, 32, 67, 248, 22, 75, 69,
						204, 133, 63, 183, 69, 249, 109, 238, 34, 102, 105, 215,
						230, 240, 78, 154, 20, 21, 47,
					],
					[
						250, 246, 60, 49, 140, 211, 134, 151, 53, 21, 235, 46,
						18, 191, 16, 0, 107, 74, 116, 100, 79, 127, 188, 202,
						52, 151, 99, 90, 50, 214, 52, 32,
					],
					[
						236, 110, 151, 23, 55, 118, 217, 223, 90, 177, 148, 121,
						248, 153, 145, 204, 213, 116, 212, 174, 24, 126, 251,
						205, 172, 216, 173, 62, 134, 55, 208, 19,
					],
					[
						223, 111, 35, 166, 28, 204, 216, 141, 53, 169, 23, 195,
						96, 211, 127, 104, 24, 252, 183, 234, 106, 196, 132, 13,
						27, 177, 205, 108, 124, 121, 112, 22,
					],
					[
						218, 202, 184, 89, 59, 129, 12, 213, 131, 84, 147, 202,
						118, 138, 177, 104, 119, 34, 75, 119, 121, 16, 103, 195,
						135, 233, 142, 252, 188, 114, 254, 47,
					],
					[
						21, 140, 133, 29, 226, 24, 142, 225, 117, 245, 179, 128,
						149, 76, 122, 226, 189, 213, 48, 97, 27, 183, 153, 177,
						232, 81, 32, 26, 100, 112, 151, 27,
					],
					[
						101, 213, 65, 124, 118, 36, 35, 9, 78, 130, 161, 114,
						216, 145, 185, 157, 215, 85, 66, 116, 133, 53, 154, 174,
						119, 70, 58, 243, 36, 37, 71, 39,
					],
					[
						244, 220, 183, 18, 81, 36, 238, 113, 219, 23, 193, 76,
						122, 139, 25, 80, 121, 220, 0, 25, 104, 133, 251, 220,
						91, 149, 164, 167, 109, 147, 2, 8,
					],
					[
						228, 25, 68, 110, 70, 80, 34, 2, 72, 133, 209, 32, 138,
						54, 232, 88, 83, 19, 132, 179, 8, 35, 109, 87, 2, 166,
						58, 106, 150, 141, 90, 38,
					],
					[
						46, 191, 128, 91, 39, 31, 200, 239, 132, 236, 228, 124,
						60, 182, 49, 124, 2, 5, 152, 182, 99, 150, 250, 48, 255,
						28, 146, 120, 222, 119, 234, 29,
					],
					[
						216, 238, 89, 44, 232, 231, 210, 176, 231, 93, 62, 205,
						151, 216, 228, 6, 118, 19, 5, 97, 94, 136, 18, 82, 182,
						174, 215, 13, 35, 255, 9, 43,
					],
					[
						126, 197, 33, 55, 2, 0, 38, 131, 246, 38, 88, 59, 186,
						8, 173, 236, 44, 137, 253, 112, 123, 96, 199, 23, 179,
						230, 87, 170, 126, 163, 194, 42,
					],
					[
						131, 156, 235, 19, 189, 142, 146, 169, 144, 60, 172,
						236, 177, 16, 101, 111, 196, 104, 170, 220, 94, 222,
						240, 16, 129, 25, 117, 250, 128, 135, 152, 39,
					],
				],
				colHat: [
					[
						165, 236, 212, 219, 132, 145, 85, 19, 201, 161, 152,
						236, 222, 230, 84, 165, 58, 118, 126, 44, 164, 3, 234,
						19, 21, 26, 216, 161, 52, 60, 106, 10,
					],
					[
						214, 114, 76, 73, 94, 67, 225, 50, 12, 225, 18, 31, 254,
						131, 112, 77, 91, 80, 229, 23, 85, 87, 149, 145, 99,
						176, 208, 99, 206, 95, 142, 30,
					],
					[
						118, 72, 32, 66, 203, 69, 234, 112, 245, 5, 36, 101,
						249, 238, 189, 128, 198, 230, 57, 23, 46, 25, 140, 208,
						163, 72, 223, 146, 139, 24, 133, 4,
					],
					[
						46, 234, 236, 202, 145, 8, 209, 113, 43, 172, 94, 230,
						110, 27, 202, 137, 49, 79, 94, 17, 226, 91, 133, 17,
						189, 172, 32, 45, 1, 178, 147, 2,
					],
					[
						28, 124, 227, 1, 3, 33, 7, 164, 76, 156, 23, 35, 120,
						154, 185, 126, 129, 82, 220, 113, 243, 232, 67, 41, 60,
						81, 188, 141, 196, 97, 234, 8,
					],
					[
						30, 64, 18, 203, 80, 242, 182, 131, 138, 84, 155, 84,
						119, 120, 145, 111, 168, 77, 172, 138, 174, 226, 146,
						86, 139, 64, 249, 178, 186, 231, 136, 39,
					],
					[
						155, 251, 219, 245, 98, 61, 233, 48, 47, 236, 21, 110,
						145, 127, 15, 206, 44, 248, 196, 89, 119, 30, 34, 174,
						194, 61, 67, 28, 123, 42, 82, 8,
					],
					[
						164, 176, 130, 219, 60, 136, 228, 200, 191, 129, 216,
						94, 133, 81, 51, 105, 70, 172, 150, 189, 170, 159, 85,
						14, 217, 227, 22, 197, 204, 231, 95, 37,
					],
					[
						36, 87, 71, 235, 237, 18, 219, 244, 3, 180, 125, 91,
						105, 25, 118, 44, 84, 3, 20, 91, 62, 7, 40, 133, 216,
						215, 112, 235, 27, 99, 148, 28,
					],
					[
						13, 36, 27, 175, 246, 30, 140, 40, 88, 37, 221, 250,
						178, 7, 214, 105, 128, 227, 167, 208, 1, 48, 251, 241,
						90, 3, 64, 76, 23, 130, 201, 45,
					],
					[
						91, 132, 166, 82, 220, 154, 39, 37, 140, 85, 187, 16,
						25, 222, 131, 188, 246, 124, 154, 163, 181, 204, 173,
						131, 226, 52, 226, 127, 246, 17, 8, 21,
					],
					[
						248, 130, 210, 129, 215, 128, 224, 110, 130, 5, 232,
						158, 212, 98, 138, 62, 189, 58, 245, 200, 47, 249, 140,
						58, 197, 137, 0, 220, 223, 185, 159, 20,
					],
					[
						48, 114, 93, 238, 202, 114, 4, 100, 78, 233, 144, 159,
						72, 113, 149, 122, 214, 33, 249, 74, 175, 237, 165, 31,
						17, 12, 130, 57, 172, 132, 224, 26,
					],
					[
						143, 8, 26, 230, 26, 248, 53, 249, 240, 254, 184, 63,
						199, 103, 66, 87, 202, 64, 160, 137, 238, 184, 242, 88,
						30, 223, 107, 167, 230, 209, 106, 9,
					],
					[
						238, 182, 165, 192, 214, 39, 245, 215, 138, 214, 199,
						143, 113, 108, 208, 33, 55, 117, 80, 136, 56, 122, 12,
						78, 222, 221, 24, 109, 215, 154, 184, 4,
					],
					[
						152, 63, 149, 141, 35, 231, 118, 103, 162, 217, 83, 186,
						60, 49, 158, 103, 19, 104, 77, 4, 38, 25, 41, 240, 222,
						58, 95, 8, 251, 47, 144, 10,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						53, 23, 66, 205, 214, 6, 45, 128, 149, 203, 44, 217,
						240, 53, 143, 82, 16, 224, 148, 114, 43, 24, 204, 132,
						232, 67, 22, 99, 85, 66, 64, 37,
					],
					[
						197, 126, 43, 204, 39, 31, 179, 247, 179, 128, 38, 41,
						213, 232, 136, 187, 116, 99, 249, 152, 213, 208, 120,
						235, 204, 56, 234, 118, 218, 242, 43, 24,
					],
					[
						86, 252, 55, 154, 38, 0, 68, 136, 93, 17, 231, 28, 218,
						27, 38, 176, 165, 55, 130, 53, 44, 166, 248, 160, 27, 0,
						212, 103, 12, 170, 235, 23,
					],
					[
						52, 48, 128, 253, 166, 83, 106, 225, 89, 210, 147, 226,
						119, 133, 99, 115, 60, 178, 207, 199, 70, 46, 237, 4,
						23, 156, 127, 251, 1, 81, 200, 8,
					],
					[
						106, 80, 15, 242, 98, 254, 142, 67, 54, 70, 253, 225,
						116, 160, 119, 84, 99, 177, 74, 178, 68, 215, 181, 8,
						113, 152, 212, 211, 83, 150, 114, 44,
					],
					[
						244, 7, 127, 187, 89, 1, 218, 117, 151, 63, 79, 85, 140,
						248, 119, 65, 109, 75, 207, 25, 69, 81, 243, 25, 181,
						239, 175, 85, 113, 185, 145, 3,
					],
					[
						8, 4, 202, 45, 94, 195, 152, 76, 101, 245, 238, 52, 178,
						197, 229, 91, 41, 31, 207, 158, 8, 13, 104, 244, 53, 3,
						224, 48, 165, 115, 55, 15,
					],
					[
						120, 68, 157, 34, 164, 15, 21, 72, 6, 97, 107, 229, 147,
						111, 241, 210, 188, 193, 221, 66, 33, 124, 17, 201, 247,
						66, 70, 244, 4, 114, 21, 46,
					],
					[
						44, 10, 118, 46, 25, 251, 206, 116, 21, 234, 53, 101, 5,
						54, 108, 241, 55, 226, 168, 72, 179, 122, 214, 36, 193,
						255, 130, 179, 170, 22, 37, 27,
					],
					[
						243, 105, 157, 248, 190, 147, 246, 78, 252, 167, 142,
						41, 213, 56, 227, 186, 1, 41, 103, 151, 132, 119, 50,
						164, 94, 215, 138, 17, 255, 7, 167, 24,
					],
					[
						47, 161, 189, 59, 50, 129, 77, 80, 112, 82, 222, 202,
						55, 48, 73, 19, 39, 146, 43, 59, 70, 27, 10, 90, 48,
						196, 41, 97, 69, 19, 55, 23,
					],
					[
						186, 101, 98, 54, 8, 210, 107, 154, 151, 128, 239, 66,
						201, 87, 84, 163, 81, 78, 7, 82, 63, 125, 77, 59, 18,
						192, 102, 252, 255, 76, 140, 23,
					],
					[
						220, 9, 248, 164, 205, 203, 214, 81, 25, 26, 60, 90,
						252, 153, 201, 121, 58, 250, 87, 171, 36, 197, 18, 104,
						148, 52, 130, 124, 183, 231, 80, 0,
					],
					[
						122, 187, 221, 43, 228, 75, 181, 171, 99, 157, 240, 115,
						2, 59, 199, 199, 95, 156, 151, 152, 126, 184, 84, 136,
						138, 118, 132, 4, 86, 62, 44, 4,
					],
					[
						81, 189, 228, 64, 61, 163, 9, 231, 123, 180, 195, 240,
						193, 170, 150, 44, 58, 139, 172, 194, 39, 23, 30, 74,
						30, 214, 125, 196, 213, 143, 225, 10,
					],
					[
						4, 151, 4, 212, 19, 139, 106, 128, 27, 179, 113, 106,
						140, 102, 131, 231, 61, 202, 79, 186, 134, 150, 148,
						125, 7, 9, 80, 110, 35, 101, 2, 25,
					],
				],
				colHat: [
					[
						73, 125, 64, 68, 52, 133, 118, 87, 101, 12, 242, 129,
						193, 90, 216, 72, 103, 152, 214, 194, 191, 92, 48, 233,
						26, 7, 111, 224, 231, 114, 207, 42,
					],
					[
						118, 219, 79, 242, 150, 67, 224, 67, 87, 78, 107, 186,
						101, 189, 168, 113, 151, 108, 161, 87, 167, 219, 15, 57,
						81, 33, 78, 154, 15, 7, 82, 6,
					],
					[
						220, 204, 214, 10, 140, 90, 199, 5, 254, 45, 17, 14, 22,
						157, 30, 250, 252, 71, 94, 249, 51, 21, 41, 39, 245, 98,
						218, 127, 109, 134, 165, 22,
					],
					[
						214, 1, 37, 179, 155, 185, 244, 4, 236, 24, 138, 77,
						235, 244, 197, 200, 152, 159, 22, 185, 147, 240, 4, 134,
						54, 111, 228, 105, 136, 44, 16, 3,
					],
					[
						244, 10, 62, 119, 70, 154, 226, 180, 19, 21, 109, 167,
						173, 218, 111, 241, 128, 125, 203, 57, 163, 13, 208,
						225, 37, 167, 194, 1, 163, 220, 43, 47,
					],
					[
						22, 134, 248, 233, 204, 49, 116, 218, 49, 33, 107, 237,
						95, 202, 96, 177, 13, 208, 205, 139, 102, 51, 197, 100,
						119, 100, 2, 130, 164, 196, 204, 36,
					],
					[
						216, 236, 126, 192, 230, 168, 120, 19, 240, 186, 144,
						179, 35, 137, 133, 165, 63, 119, 100, 12, 207, 1, 109,
						238, 204, 69, 241, 202, 79, 145, 0, 32,
					],
					[
						155, 37, 43, 236, 225, 219, 156, 170, 33, 45, 178, 6,
						159, 117, 174, 15, 24, 208, 90, 131, 0, 92, 218, 10,
						179, 96, 108, 18, 49, 191, 78, 38,
					],
					[
						86, 142, 251, 1, 93, 48, 177, 246, 85, 39, 107, 148, 81,
						55, 98, 206, 89, 97, 42, 219, 10, 68, 187, 144, 154, 62,
						69, 223, 139, 183, 152, 36,
					],
					[
						55, 164, 47, 242, 8, 1, 52, 178, 14, 59, 250, 248, 88,
						35, 36, 247, 219, 2, 181, 228, 175, 222, 216, 155, 149,
						174, 234, 100, 57, 141, 240, 10,
					],
					[
						79, 239, 127, 209, 149, 116, 128, 200, 84, 227, 229, 19,
						181, 76, 68, 183, 64, 148, 158, 247, 171, 132, 18, 73,
						64, 229, 159, 188, 35, 145, 121, 6,
					],
					[
						67, 150, 235, 57, 42, 18, 161, 78, 205, 218, 218, 123,
						80, 66, 65, 155, 157, 213, 161, 83, 236, 146, 204, 239,
						26, 91, 104, 4, 63, 1, 86, 8,
					],
					[
						161, 52, 150, 107, 25, 230, 157, 123, 173, 217, 159, 14,
						231, 162, 225, 150, 251, 171, 14, 47, 92, 62, 9, 142,
						188, 250, 206, 22, 182, 105, 36, 7,
					],
					[
						210, 160, 147, 250, 176, 157, 225, 153, 114, 199, 80,
						70, 254, 146, 186, 211, 214, 18, 134, 65, 165, 177, 142,
						239, 217, 97, 183, 116, 6, 240, 237, 17,
					],
					[
						209, 182, 252, 113, 80, 212, 131, 227, 72, 235, 163, 16,
						120, 95, 99, 22, 126, 20, 30, 197, 11, 156, 160, 72,
						209, 203, 83, 174, 217, 163, 17, 11,
					],
					[
						130, 224, 220, 84, 209, 247, 190, 131, 210, 246, 203,
						149, 132, 208, 166, 209, 246, 210, 212, 63, 170, 173,
						203, 113, 109, 160, 174, 199, 140, 33, 16, 31,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						208, 179, 255, 32, 226, 4, 4, 198, 22, 141, 34, 46, 218,
						111, 165, 0, 38, 235, 28, 237, 24, 115, 159, 23, 56, 7,
						226, 205, 179, 82, 23, 37,
					],
					[
						104, 24, 83, 132, 86, 14, 134, 0, 246, 127, 75, 126,
						166, 234, 31, 151, 12, 218, 132, 31, 203, 184, 236, 207,
						168, 62, 48, 61, 112, 205, 16, 15,
					],
					[
						121, 200, 209, 136, 106, 49, 41, 96, 52, 14, 146, 131,
						174, 153, 30, 133, 8, 87, 208, 143, 7, 51, 201, 89, 226,
						120, 141, 196, 179, 167, 145, 39,
					],
					[
						22, 21, 113, 170, 67, 62, 238, 32, 229, 225, 208, 239,
						123, 253, 166, 54, 171, 182, 11, 58, 171, 143, 213, 25,
						41, 8, 88, 218, 167, 82, 137, 25,
					],
					[
						104, 85, 254, 225, 63, 22, 160, 154, 171, 0, 231, 134,
						188, 60, 208, 67, 224, 91, 191, 198, 150, 134, 145, 193,
						106, 212, 132, 13, 255, 162, 44, 4,
					],
					[
						39, 114, 247, 203, 208, 172, 167, 57, 64, 3, 139, 153,
						117, 69, 202, 32, 131, 252, 176, 134, 232, 54, 173, 86,
						208, 92, 74, 162, 173, 53, 110, 3,
					],
					[
						47, 178, 67, 29, 239, 128, 15, 120, 88, 14, 10, 223,
						132, 94, 46, 175, 132, 14, 154, 174, 240, 80, 135, 136,
						182, 78, 130, 69, 130, 78, 127, 38,
					],
					[
						141, 26, 203, 138, 18, 19, 101, 172, 156, 143, 116, 54,
						166, 237, 195, 56, 62, 11, 13, 154, 215, 170, 42, 112,
						194, 84, 207, 89, 92, 239, 230, 14,
					],
					[
						223, 144, 156, 163, 251, 176, 47, 35, 250, 155, 165,
						163, 253, 73, 2, 3, 233, 11, 83, 24, 94, 129, 100, 170,
						79, 185, 128, 245, 209, 251, 22, 14,
					],
					[
						55, 170, 119, 213, 141, 182, 135, 193, 71, 157, 46, 115,
						100, 141, 198, 22, 25, 107, 192, 195, 4, 98, 151, 15,
						42, 58, 131, 144, 247, 77, 114, 9,
					],
					[
						20, 230, 35, 56, 50, 117, 34, 42, 240, 180, 172, 185,
						123, 245, 186, 220, 182, 240, 22, 104, 243, 90, 7, 33,
						3, 24, 113, 19, 231, 96, 187, 3,
					],
					[
						74, 121, 101, 248, 49, 130, 46, 176, 221, 143, 136, 189,
						74, 44, 228, 107, 164, 13, 236, 51, 44, 241, 229, 63,
						26, 195, 17, 46, 125, 4, 49, 13,
					],
					[
						10, 91, 79, 95, 180, 86, 129, 71, 20, 138, 180, 200,
						162, 207, 220, 130, 110, 160, 118, 200, 189, 190, 101,
						163, 196, 36, 161, 232, 69, 228, 16, 41,
					],
					[
						177, 17, 82, 232, 152, 239, 120, 34, 147, 89, 229, 182,
						167, 95, 30, 217, 126, 17, 49, 243, 53, 19, 44, 133, 56,
						73, 87, 38, 199, 227, 76, 32,
					],
					[
						114, 62, 75, 237, 147, 236, 172, 61, 140, 191, 41, 39,
						20, 39, 4, 72, 38, 40, 6, 152, 114, 156, 166, 8, 223,
						166, 56, 27, 162, 135, 28, 16,
					],
					[
						171, 110, 196, 38, 99, 81, 98, 84, 21, 88, 86, 235, 71,
						72, 61, 152, 71, 193, 54, 191, 47, 135, 121, 212, 170,
						243, 172, 129, 164, 32, 162, 0,
					],
				],
				colHat: [
					[
						173, 224, 245, 66, 3, 87, 186, 144, 164, 24, 50, 163,
						146, 202, 109, 155, 50, 249, 192, 68, 30, 9, 150, 73,
						78, 205, 141, 113, 42, 5, 123, 23,
					],
					[
						118, 23, 171, 242, 84, 106, 16, 203, 100, 242, 81, 117,
						137, 42, 200, 247, 71, 129, 9, 172, 92, 15, 174, 25,
						151, 80, 245, 81, 88, 66, 194, 41,
					],
					[
						183, 173, 148, 76, 230, 198, 132, 161, 24, 202, 120,
						189, 191, 245, 19, 67, 68, 48, 196, 77, 73, 217, 38,
						206, 151, 64, 74, 172, 138, 237, 7, 14,
					],
					[
						77, 108, 2, 71, 152, 233, 160, 173, 46, 75, 192, 94,
						204, 237, 223, 147, 237, 20, 61, 203, 241, 188, 155, 39,
						99, 94, 43, 99, 167, 237, 147, 17,
					],
					[
						158, 164, 118, 15, 30, 153, 16, 244, 214, 170, 125, 211,
						149, 33, 157, 249, 137, 183, 57, 251, 164, 109, 201,
						250, 60, 221, 83, 238, 187, 150, 191, 46,
					],
					[
						28, 194, 102, 74, 117, 250, 44, 211, 211, 204, 52, 21,
						111, 227, 104, 171, 78, 191, 222, 183, 126, 20, 39, 187,
						241, 6, 31, 88, 23, 117, 140, 24,
					],
					[
						18, 28, 139, 136, 44, 161, 239, 65, 47, 66, 44, 7, 234,
						196, 187, 49, 120, 58, 248, 47, 235, 33, 107, 35, 14,
						70, 150, 42, 72, 86, 44, 13,
					],
					[
						34, 136, 67, 220, 41, 143, 164, 24, 77, 139, 2, 22, 14,
						52, 135, 199, 189, 6, 222, 110, 57, 18, 158, 87, 63, 87,
						41, 246, 107, 104, 106, 39,
					],
					[
						208, 149, 71, 38, 141, 37, 12, 42, 94, 40, 132, 243,
						199, 47, 170, 235, 111, 109, 180, 159, 6, 0, 167, 64,
						62, 208, 48, 10, 87, 138, 64, 9,
					],
					[
						255, 72, 198, 158, 129, 149, 229, 236, 78, 95, 66, 128,
						234, 219, 158, 173, 18, 251, 7, 64, 45, 244, 157, 167,
						131, 111, 59, 54, 161, 96, 124, 11,
					],
					[
						85, 21, 81, 85, 71, 112, 47, 250, 143, 109, 178, 91,
						229, 232, 65, 158, 107, 51, 42, 253, 146, 245, 146, 241,
						242, 227, 238, 143, 5, 22, 143, 46,
					],
					[
						76, 34, 38, 69, 133, 149, 27, 107, 53, 152, 224, 28, 66,
						147, 66, 165, 27, 120, 207, 114, 70, 214, 181, 73, 214,
						63, 226, 219, 87, 126, 173, 16,
					],
					[
						180, 71, 135, 181, 208, 112, 246, 224, 33, 157, 212,
						230, 234, 147, 25, 8, 11, 8, 247, 44, 15, 222, 229, 154,
						224, 17, 229, 120, 158, 17, 131, 25,
					],
					[
						1, 147, 199, 222, 248, 161, 6, 118, 6, 207, 253, 35,
						219, 181, 248, 125, 182, 181, 49, 102, 155, 238, 245,
						242, 190, 215, 203, 46, 174, 170, 137, 20,
					],
					[
						60, 198, 233, 136, 80, 33, 228, 51, 154, 2, 63, 13, 40,
						208, 229, 61, 209, 14, 239, 184, 217, 213, 19, 15, 58,
						150, 214, 190, 46, 137, 186, 27,
					],
					[
						158, 24, 1, 244, 90, 246, 68, 35, 101, 60, 142, 12, 57,
						216, 141, 192, 24, 138, 181, 115, 16, 51, 36, 240, 132,
						59, 12, 89, 203, 23, 134, 37,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						55, 144, 182, 198, 117, 67, 6, 55, 84, 227, 39, 77, 151,
						113, 218, 89, 114, 150, 5, 37, 53, 221, 73, 242, 146,
						225, 43, 26, 139, 53, 120, 37,
					],
					[
						198, 26, 21, 69, 140, 107, 114, 32, 42, 68, 159, 168,
						86, 35, 6, 142, 135, 108, 165, 64, 211, 74, 50, 108, 19,
						108, 136, 120, 83, 12, 171, 20,
					],
					[
						233, 212, 150, 190, 6, 171, 233, 15, 218, 158, 245, 86,
						193, 97, 64, 192, 86, 124, 18, 237, 148, 135, 42, 135,
						156, 73, 43, 98, 94, 22, 32, 38,
					],
					[
						83, 171, 255, 237, 233, 14, 185, 141, 95, 38, 21, 70,
						220, 79, 229, 49, 185, 221, 129, 202, 170, 192, 105,
						225, 31, 148, 93, 32, 68, 100, 21, 36,
					],
					[
						38, 44, 22, 73, 11, 180, 156, 192, 22, 77, 239, 11, 218,
						246, 40, 168, 209, 237, 68, 115, 245, 255, 121, 97, 164,
						201, 146, 220, 66, 118, 96, 48,
					],
					[
						33, 184, 183, 154, 57, 99, 103, 132, 224, 187, 158, 0,
						34, 25, 173, 154, 65, 172, 156, 171, 115, 200, 165, 70,
						25, 76, 211, 48, 184, 152, 138, 17,
					],
					[
						58, 177, 60, 117, 172, 107, 137, 88, 7, 38, 154, 1, 142,
						35, 166, 205, 158, 145, 59, 71, 46, 254, 209, 132, 233,
						146, 74, 162, 140, 178, 253, 19,
					],
					[
						74, 9, 172, 20, 195, 203, 181, 17, 42, 78, 14, 15, 222,
						142, 99, 72, 94, 198, 230, 61, 213, 72, 85, 89, 118, 68,
						57, 126, 228, 3, 218, 23,
					],
					[
						189, 135, 61, 30, 57, 40, 181, 79, 131, 56, 51, 86, 121,
						252, 48, 110, 145, 245, 62, 237, 105, 216, 230, 241,
						129, 187, 98, 219, 113, 23, 52, 25,
					],
					[
						84, 99, 117, 128, 39, 201, 169, 218, 251, 222, 209, 135,
						185, 112, 50, 214, 149, 30, 210, 231, 54, 115, 73, 30,
						40, 72, 130, 246, 216, 129, 20, 8,
					],
					[
						53, 228, 41, 130, 35, 162, 67, 22, 51, 153, 153, 125,
						92, 45, 214, 134, 134, 185, 245, 32, 126, 83, 248, 37,
						226, 48, 168, 180, 102, 94, 210, 11,
					],
					[
						106, 165, 168, 155, 110, 204, 248, 233, 250, 71, 20, 46,
						153, 181, 117, 229, 152, 45, 30, 198, 225, 62, 243, 25,
						207, 12, 100, 156, 196, 84, 58, 21,
					],
					[
						39, 121, 242, 180, 225, 49, 67, 205, 44, 56, 196, 95,
						154, 65, 97, 175, 133, 57, 85, 24, 225, 180, 104, 14,
						178, 171, 217, 195, 10, 5, 24, 37,
					],
					[
						64, 101, 30, 126, 158, 177, 240, 66, 165, 249, 93, 207,
						48, 253, 120, 167, 31, 156, 89, 210, 105, 68, 74, 166,
						194, 16, 209, 79, 100, 242, 134, 10,
					],
					[
						176, 34, 79, 113, 178, 123, 48, 165, 126, 63, 127, 150,
						29, 66, 226, 218, 143, 90, 111, 210, 158, 218, 84, 85,
						176, 164, 22, 109, 45, 35, 115, 13,
					],
					[
						230, 232, 5, 54, 154, 215, 169, 8, 209, 77, 197, 155,
						204, 62, 255, 143, 162, 195, 224, 35, 172, 15, 146, 222,
						57, 199, 26, 61, 154, 112, 67, 14,
					],
				],
				colHat: [
					[
						181, 178, 246, 210, 47, 206, 104, 12, 173, 104, 81, 155,
						61, 56, 74, 235, 145, 210, 35, 176, 171, 215, 74, 133,
						23, 190, 190, 151, 87, 28, 239, 16,
					],
					[
						23, 70, 246, 172, 227, 29, 29, 115, 55, 160, 201, 194,
						250, 209, 7, 199, 113, 7, 190, 69, 66, 81, 206, 204,
						104, 204, 252, 159, 148, 146, 255, 13,
					],
					[
						81, 219, 227, 84, 27, 108, 167, 178, 14, 200, 118, 123,
						244, 159, 90, 34, 133, 22, 38, 146, 159, 181, 172, 161,
						198, 193, 13, 111, 176, 46, 224, 15,
					],
					[
						7, 251, 149, 238, 14, 154, 244, 27, 201, 113, 226, 132,
						151, 197, 96, 219, 243, 74, 248, 101, 53, 23, 213, 43,
						148, 82, 231, 9, 111, 196, 164, 9,
					],
					[
						63, 139, 58, 132, 160, 144, 114, 209, 169, 4, 127, 237,
						65, 244, 33, 158, 163, 113, 15, 6, 51, 4, 11, 67, 94,
						18, 185, 83, 168, 38, 8, 28,
					],
					[
						211, 1, 249, 111, 205, 28, 146, 100, 145, 48, 81, 108,
						217, 227, 218, 224, 73, 170, 209, 68, 12, 55, 184, 149,
						104, 19, 176, 31, 233, 251, 62, 14,
					],
					[
						210, 15, 129, 171, 207, 34, 159, 200, 199, 74, 30, 239,
						117, 206, 234, 112, 34, 90, 102, 102, 80, 188, 177, 16,
						253, 130, 114, 217, 37, 10, 162, 20,
					],
					[
						241, 204, 23, 77, 68, 177, 26, 93, 190, 100, 151, 119,
						179, 123, 248, 171, 91, 245, 143, 195, 233, 171, 140,
						155, 175, 132, 11, 215, 191, 11, 27, 27,
					],
					[
						71, 76, 219, 248, 211, 252, 192, 72, 128, 169, 143, 241,
						48, 206, 10, 1, 8, 88, 0, 50, 237, 154, 67, 92, 228, 10,
						83, 214, 177, 250, 31, 41,
					],
					[
						33, 97, 131, 74, 223, 38, 101, 66, 126, 91, 102, 142,
						56, 179, 218, 245, 61, 110, 204, 202, 66, 240, 29, 116,
						212, 173, 120, 170, 33, 106, 82, 24,
					],
					[
						132, 115, 10, 95, 81, 216, 106, 19, 228, 169, 179, 170,
						255, 116, 249, 60, 111, 155, 46, 54, 109, 37, 107, 238,
						135, 182, 67, 160, 255, 249, 48, 26,
					],
					[
						22, 64, 201, 150, 32, 164, 164, 208, 170, 174, 105, 31,
						213, 68, 12, 4, 40, 251, 198, 107, 38, 34, 135, 50, 49,
						174, 169, 44, 222, 223, 157, 11,
					],
					[
						240, 253, 67, 234, 129, 130, 36, 195, 112, 181, 97, 193,
						63, 237, 51, 134, 182, 32, 232, 188, 88, 81, 79, 174,
						71, 161, 145, 94, 72, 184, 135, 40,
					],
					[
						211, 171, 210, 129, 245, 3, 174, 243, 250, 193, 231,
						145, 105, 186, 139, 145, 148, 62, 89, 57, 92, 255, 43,
						107, 3, 203, 111, 222, 103, 50, 167, 18,
					],
					[
						81, 32, 96, 55, 236, 236, 189, 103, 143, 155, 253, 128,
						27, 178, 154, 216, 148, 226, 0, 77, 15, 219, 206, 19,
						117, 12, 163, 30, 114, 30, 174, 47,
					],
					[
						24, 254, 109, 213, 225, 168, 91, 154, 211, 54, 132, 10,
						151, 229, 247, 112, 243, 16, 11, 30, 104, 58, 59, 226,
						78, 209, 14, 168, 138, 169, 165, 17,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						85, 118, 55, 175, 5, 131, 97, 41, 61, 72, 233, 194, 115,
						73, 130, 164, 91, 244, 135, 198, 111, 241, 238, 52, 39,
						186, 33, 163, 52, 228, 136, 16,
					],
					[
						216, 108, 214, 221, 53, 247, 0, 252, 82, 105, 65, 104,
						52, 176, 179, 77, 139, 30, 225, 205, 114, 24, 42, 64,
						97, 250, 178, 179, 93, 97, 79, 22,
					],
					[
						233, 148, 244, 63, 250, 24, 87, 221, 84, 138, 41, 87,
						90, 120, 105, 203, 88, 181, 39, 0, 188, 3, 35, 130, 37,
						122, 83, 180, 218, 180, 176, 20,
					],
					[
						77, 144, 92, 195, 20, 2, 241, 213, 92, 207, 97, 159,
						118, 107, 98, 181, 182, 194, 214, 212, 137, 219, 253,
						130, 62, 4, 224, 79, 116, 38, 221, 3,
					],
					[
						95, 123, 253, 72, 121, 86, 58, 46, 227, 205, 193, 5,
						101, 144, 60, 157, 61, 142, 140, 255, 77, 200, 180, 4,
						18, 95, 175, 163, 94, 214, 226, 36,
					],
					[
						11, 73, 140, 35, 239, 131, 176, 92, 17, 76, 201, 110,
						10, 197, 234, 172, 141, 76, 147, 216, 217, 68, 178, 129,
						158, 120, 245, 30, 100, 217, 74, 19,
					],
					[
						118, 218, 98, 158, 255, 182, 239, 184, 232, 217, 38,
						248, 177, 199, 35, 138, 59, 23, 187, 166, 254, 75, 1,
						233, 236, 77, 60, 123, 44, 139, 4, 45,
					],
					[
						132, 220, 230, 224, 35, 225, 16, 9, 13, 212, 146, 126,
						72, 177, 229, 244, 91, 114, 16, 90, 49, 28, 9, 225, 39,
						119, 191, 250, 204, 92, 137, 18,
					],
					[
						250, 231, 100, 83, 2, 146, 22, 226, 23, 234, 18, 50, 42,
						115, 38, 182, 147, 56, 227, 73, 151, 8, 254, 231, 245,
						22, 174, 232, 159, 49, 119, 0,
					],
					[
						58, 14, 197, 244, 167, 77, 30, 106, 180, 238, 58, 58,
						174, 238, 187, 19, 237, 12, 215, 221, 206, 148, 79, 64,
						69, 255, 198, 116, 245, 82, 130, 38,
					],
					[
						115, 116, 207, 133, 109, 209, 9, 127, 124, 223, 106,
						128, 71, 72, 22, 157, 129, 201, 170, 147, 82, 16, 25,
						82, 94, 57, 35, 242, 201, 191, 75, 26,
					],
					[
						134, 174, 23, 188, 91, 123, 130, 189, 249, 16, 134, 189,
						96, 70, 166, 136, 42, 33, 85, 232, 174, 203, 25, 73,
						161, 31, 117, 34, 29, 10, 101, 34,
					],
					[
						147, 52, 236, 134, 218, 80, 90, 219, 18, 96, 213, 122,
						191, 188, 181, 41, 167, 53, 85, 137, 184, 224, 251, 84,
						53, 86, 242, 229, 21, 243, 212, 25,
					],
					[
						158, 255, 104, 50, 204, 141, 75, 58, 77, 169, 249, 110,
						67, 211, 169, 20, 148, 86, 78, 225, 27, 181, 185, 146,
						1, 97, 170, 25, 186, 38, 243, 27,
					],
					[
						92, 181, 104, 187, 96, 231, 15, 114, 243, 181, 170, 174,
						127, 96, 150, 118, 127, 123, 101, 152, 32, 143, 92, 197,
						10, 49, 67, 210, 68, 238, 5, 39,
					],
					[
						181, 241, 164, 246, 202, 204, 206, 135, 7, 113, 59, 74,
						36, 130, 228, 57, 85, 169, 68, 208, 72, 196, 212, 157,
						230, 222, 160, 55, 121, 130, 58, 5,
					],
				],
				colHat: [
					[
						143, 0, 77, 66, 105, 253, 176, 202, 217, 229, 168, 64,
						28, 71, 87, 56, 190, 147, 227, 235, 121, 251, 141, 188,
						181, 148, 205, 198, 43, 225, 103, 39,
					],
					[
						37, 108, 69, 152, 246, 136, 169, 129, 32, 199, 226, 64,
						122, 77, 185, 3, 170, 162, 91, 210, 237, 91, 61, 70, 86,
						6, 125, 165, 225, 119, 20, 35,
					],
					[
						232, 77, 137, 54, 230, 55, 46, 78, 110, 148, 73, 3, 0,
						247, 148, 206, 4, 121, 231, 223, 19, 246, 203, 175, 176,
						35, 74, 21, 72, 21, 120, 22,
					],
					[
						57, 115, 24, 114, 181, 249, 249, 89, 110, 36, 181, 94,
						31, 136, 173, 81, 112, 227, 196, 134, 229, 142, 117,
						190, 36, 47, 48, 166, 238, 90, 44, 32,
					],
					[
						189, 43, 153, 59, 160, 24, 93, 222, 235, 53, 140, 167,
						156, 1, 201, 52, 94, 236, 10, 202, 133, 159, 66, 171,
						102, 47, 69, 218, 86, 232, 33, 29,
					],
					[
						120, 242, 153, 234, 89, 229, 128, 242, 83, 250, 233, 55,
						106, 180, 178, 247, 252, 95, 64, 172, 240, 222, 250,
						172, 64, 144, 205, 209, 79, 18, 123, 31,
					],
					[
						212, 228, 87, 98, 175, 148, 126, 115, 33, 181, 216, 252,
						157, 82, 141, 129, 165, 143, 117, 249, 248, 127, 248,
						81, 103, 187, 160, 16, 151, 10, 75, 46,
					],
					[
						56, 215, 98, 137, 150, 22, 54, 180, 179, 77, 172, 204,
						3, 64, 244, 68, 30, 49, 243, 53, 45, 53, 31, 110, 68,
						93, 17, 91, 41, 244, 251, 22,
					],
					[
						9, 50, 61, 7, 49, 4, 195, 98, 88, 199, 65, 196, 68, 113,
						252, 181, 213, 66, 212, 210, 193, 41, 29, 115, 78, 13,
						232, 78, 206, 137, 247, 7,
					],
					[
						66, 66, 201, 38, 243, 62, 238, 239, 98, 6, 224, 136, 0,
						253, 10, 11, 253, 48, 197, 84, 139, 152, 16, 41, 81, 69,
						90, 171, 234, 134, 155, 16,
					],
					[
						190, 159, 131, 218, 225, 231, 225, 197, 163, 95, 132,
						154, 97, 69, 59, 211, 132, 92, 93, 99, 19, 50, 227, 210,
						239, 203, 121, 79, 130, 217, 102, 2,
					],
					[
						165, 23, 138, 17, 217, 222, 49, 81, 71, 162, 214, 200,
						91, 203, 148, 115, 219, 232, 7, 174, 166, 125, 124, 4,
						30, 41, 132, 242, 76, 132, 92, 29,
					],
					[
						152, 107, 106, 177, 107, 102, 54, 253, 214, 19, 34, 56,
						96, 18, 28, 251, 32, 30, 4, 248, 12, 174, 102, 214, 242,
						53, 121, 129, 126, 20, 170, 47,
					],
					[
						22, 3, 79, 167, 212, 220, 10, 69, 238, 10, 44, 9, 64,
						81, 199, 202, 70, 48, 181, 200, 13, 125, 240, 30, 238,
						139, 186, 11, 160, 249, 73, 38,
					],
					[
						172, 244, 206, 191, 105, 14, 61, 160, 14, 1, 45, 117,
						88, 206, 117, 107, 29, 187, 245, 71, 146, 238, 33, 61,
						101, 116, 207, 218, 125, 92, 13, 22,
					],
					[
						197, 157, 211, 61, 243, 196, 179, 97, 26, 7, 214, 36,
						108, 209, 11, 24, 24, 138, 19, 242, 128, 170, 170, 107,
						113, 192, 83, 34, 192, 50, 90, 20,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						210, 87, 3, 17, 255, 141, 179, 168, 242, 148, 192, 196,
						100, 156, 129, 235, 183, 160, 96, 212, 160, 71, 77, 158,
						100, 67, 227, 251, 123, 16, 189, 46,
					],
					[
						166, 73, 103, 242, 191, 169, 52, 29, 228, 121, 126, 120,
						154, 248, 119, 122, 79, 92, 178, 240, 197, 187, 241, 35,
						214, 190, 220, 99, 91, 6, 168, 29,
					],
					[
						83, 56, 177, 139, 71, 194, 118, 239, 54, 14, 25, 72,
						107, 92, 243, 67, 82, 97, 218, 49, 216, 72, 175, 122,
						248, 104, 184, 222, 71, 147, 55, 21,
					],
					[
						57, 134, 157, 187, 244, 149, 96, 96, 97, 242, 28, 33,
						251, 61, 75, 184, 241, 197, 7, 236, 87, 170, 36, 252,
						171, 114, 35, 32, 176, 51, 114, 12,
					],
					[
						191, 168, 22, 254, 122, 161, 236, 108, 148, 120, 243,
						121, 148, 13, 9, 82, 9, 10, 41, 50, 170, 177, 29, 68,
						44, 28, 48, 109, 174, 5, 31, 2,
					],
					[
						106, 112, 149, 245, 120, 227, 65, 199, 70, 21, 177, 211,
						246, 101, 98, 127, 36, 219, 25, 77, 2, 112, 4, 190, 114,
						152, 246, 247, 116, 99, 112, 3,
					],
					[
						56, 93, 134, 212, 68, 25, 13, 240, 80, 105, 208, 148,
						10, 141, 160, 183, 91, 254, 161, 229, 225, 129, 243, 50,
						134, 69, 200, 47, 107, 105, 65, 6,
					],
					[
						15, 157, 244, 10, 92, 188, 207, 15, 198, 53, 136, 84,
						69, 56, 2, 65, 194, 140, 37, 155, 135, 75, 196, 15, 117,
						49, 121, 153, 83, 120, 252, 45,
					],
					[
						238, 239, 62, 137, 145, 179, 66, 103, 196, 207, 52, 221,
						202, 138, 127, 83, 247, 158, 32, 71, 89, 228, 185, 3,
						175, 97, 217, 15, 152, 138, 7, 46,
					],
					[
						189, 21, 1, 143, 45, 176, 203, 22, 190, 238, 71, 238,
						147, 128, 242, 246, 57, 3, 205, 214, 115, 81, 64, 239,
						123, 177, 240, 93, 70, 154, 118, 42,
					],
					[
						3, 202, 8, 94, 217, 48, 133, 195, 89, 34, 162, 236, 90,
						127, 117, 125, 142, 35, 240, 204, 196, 19, 71, 208, 203,
						123, 66, 243, 224, 181, 246, 36,
					],
					[
						232, 2, 14, 142, 157, 45, 92, 156, 93, 179, 111, 38,
						226, 225, 86, 91, 77, 139, 242, 237, 1, 240, 185, 98,
						129, 143, 9, 83, 77, 230, 194, 29,
					],
					[
						211, 2, 215, 232, 64, 106, 24, 249, 123, 45, 116, 178,
						94, 66, 116, 130, 195, 25, 30, 130, 127, 234, 238, 54,
						21, 250, 47, 10, 38, 168, 112, 18,
					],
					[
						42, 119, 213, 230, 93, 134, 35, 173, 227, 12, 232, 185,
						62, 173, 80, 88, 254, 29, 167, 239, 59, 17, 0, 40, 147,
						227, 142, 30, 31, 175, 114, 3,
					],
					[
						219, 193, 224, 223, 250, 27, 178, 76, 135, 63, 203, 201,
						2, 148, 159, 129, 194, 23, 254, 187, 107, 155, 161, 235,
						125, 208, 251, 71, 176, 96, 162, 24,
					],
					[
						171, 167, 73, 116, 172, 106, 211, 40, 208, 58, 50, 46,
						248, 254, 154, 23, 173, 20, 41, 243, 146, 168, 59, 216,
						104, 249, 55, 68, 75, 206, 230, 47,
					],
				],
				colHat: [
					[
						97, 34, 113, 100, 1, 228, 231, 196, 129, 249, 187, 197,
						187, 186, 228, 93, 47, 255, 10, 194, 43, 100, 208, 0,
						228, 0, 6, 132, 170, 220, 83, 18,
					],
					[
						142, 106, 91, 186, 151, 244, 46, 59, 50, 93, 206, 203,
						106, 220, 142, 104, 6, 237, 211, 223, 208, 229, 203, 43,
						28, 174, 153, 40, 210, 37, 12, 9,
					],
					[
						232, 205, 158, 32, 117, 62, 170, 20, 197, 0, 231, 222,
						181, 50, 17, 32, 171, 2, 46, 158, 147, 134, 68, 246, 11,
						143, 26, 106, 167, 82, 0, 22,
					],
					[
						230, 178, 178, 172, 191, 221, 28, 34, 240, 83, 133, 110,
						30, 118, 132, 11, 19, 181, 81, 214, 150, 138, 138, 197,
						39, 9, 108, 197, 1, 94, 158, 18,
					],
					[
						192, 128, 0, 182, 136, 34, 254, 58, 207, 237, 253, 72,
						160, 174, 170, 166, 29, 110, 194, 92, 226, 213, 62, 31,
						218, 64, 152, 190, 10, 42, 249, 7,
					],
					[
						40, 64, 236, 197, 223, 68, 88, 233, 160, 160, 1, 82, 82,
						196, 31, 156, 155, 36, 24, 236, 179, 48, 55, 163, 19,
						30, 183, 190, 177, 50, 227, 27,
					],
					[
						105, 145, 226, 170, 174, 254, 103, 173, 68, 240, 194, 6,
						143, 2, 15, 103, 187, 185, 86, 201, 50, 239, 33, 86,
						147, 126, 58, 178, 92, 55, 106, 27,
					],
					[
						251, 187, 92, 203, 93, 65, 216, 134, 246, 64, 111, 8,
						188, 112, 108, 70, 138, 72, 152, 251, 136, 40, 53, 73,
						9, 57, 142, 199, 3, 24, 151, 14,
					],
					[
						81, 88, 103, 147, 117, 79, 0, 183, 0, 203, 176, 29, 23,
						131, 142, 231, 153, 130, 130, 72, 79, 249, 178, 118,
						204, 119, 213, 54, 137, 3, 82, 23,
					],
					[
						234, 238, 158, 209, 51, 168, 124, 104, 249, 84, 46, 65,
						8, 216, 68, 71, 73, 209, 19, 234, 117, 240, 208, 161,
						59, 75, 90, 91, 23, 219, 212, 2,
					],
					[
						155, 131, 242, 227, 86, 82, 141, 131, 253, 98, 229, 132,
						200, 220, 194, 117, 178, 58, 60, 244, 154, 32, 227, 227,
						135, 55, 13, 56, 39, 59, 118, 47,
					],
					[
						158, 216, 208, 214, 37, 173, 110, 187, 144, 223, 221,
						129, 243, 151, 182, 67, 171, 128, 16, 14, 137, 29, 144,
						157, 21, 125, 63, 87, 250, 57, 204, 24,
					],
					[
						102, 37, 61, 153, 136, 156, 172, 234, 187, 219, 97, 21,
						148, 63, 234, 12, 120, 61, 67, 121, 214, 187, 202, 90,
						176, 155, 51, 62, 30, 223, 234, 2,
					],
					[
						201, 19, 164, 227, 90, 27, 20, 17, 230, 109, 137, 28,
						153, 105, 174, 25, 103, 97, 143, 35, 91, 133, 242, 223,
						19, 255, 70, 177, 252, 50, 20, 39,
					],
					[
						236, 109, 81, 112, 6, 58, 33, 9, 12, 66, 213, 59, 254,
						170, 116, 237, 143, 121, 222, 236, 178, 77, 233, 225,
						235, 100, 235, 104, 150, 86, 168, 28,
					],
					[
						80, 94, 196, 179, 16, 24, 132, 6, 109, 21, 90, 147, 38,
						229, 85, 67, 194, 154, 223, 114, 188, 152, 55, 192, 246,
						208, 126, 193, 24, 128, 100, 2,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						253, 129, 54, 150, 81, 251, 79, 70, 35, 162, 237, 149,
						105, 254, 240, 190, 202, 153, 22, 109, 174, 218, 124,
						253, 154, 23, 105, 247, 173, 7, 88, 18,
					],
					[
						57, 118, 163, 83, 161, 41, 25, 116, 249, 81, 171, 99,
						157, 125, 121, 73, 125, 143, 168, 59, 172, 199, 146, 71,
						189, 209, 21, 23, 232, 23, 187, 4,
					],
					[
						6, 176, 211, 114, 98, 125, 174, 41, 61, 74, 129, 162,
						146, 65, 79, 95, 170, 209, 252, 140, 191, 176, 221, 197,
						158, 82, 168, 240, 68, 107, 70, 40,
					],
					[
						186, 73, 42, 52, 232, 50, 208, 191, 209, 237, 76, 146,
						252, 139, 164, 119, 138, 1, 175, 222, 84, 163, 11, 242,
						214, 68, 93, 39, 247, 173, 113, 43,
					],
					[
						253, 249, 81, 18, 65, 222, 12, 32, 6, 149, 219, 195,
						132, 80, 60, 226, 151, 105, 92, 165, 214, 53, 175, 161,
						87, 127, 42, 197, 231, 121, 124, 13,
					],
					[
						204, 124, 143, 76, 243, 22, 208, 95, 222, 42, 79, 98,
						102, 25, 126, 140, 128, 196, 172, 23, 198, 115, 249,
						170, 88, 189, 105, 13, 246, 45, 37, 30,
					],
					[
						158, 17, 24, 221, 33, 204, 94, 232, 156, 80, 86, 52,
						206, 25, 114, 186, 35, 125, 63, 228, 97, 47, 215, 235,
						95, 247, 102, 155, 121, 237, 227, 34,
					],
					[
						213, 94, 234, 21, 236, 100, 21, 99, 71, 150, 68, 50, 44,
						151, 242, 251, 143, 83, 88, 116, 142, 148, 0, 20, 124,
						36, 73, 85, 46, 64, 71, 9,
					],
					[
						38, 3, 218, 241, 135, 190, 43, 234, 194, 142, 84, 208,
						59, 9, 70, 41, 98, 32, 57, 168, 150, 142, 228, 33, 210,
						227, 186, 85, 19, 202, 200, 1,
					],
					[
						7, 156, 93, 138, 34, 153, 125, 47, 190, 82, 196, 46, 34,
						157, 108, 152, 90, 14, 75, 55, 70, 149, 112, 163, 117,
						205, 120, 152, 88, 131, 4, 32,
					],
					[
						119, 177, 12, 136, 201, 156, 146, 38, 45, 130, 164, 117,
						252, 210, 238, 195, 171, 170, 255, 73, 182, 33, 126, 13,
						58, 47, 166, 195, 75, 63, 9, 22,
					],
					[
						17, 180, 17, 159, 242, 233, 97, 158, 168, 246, 105, 175,
						149, 80, 76, 47, 118, 35, 114, 54, 168, 14, 83, 204, 46,
						60, 150, 174, 117, 132, 119, 23,
					],
					[
						62, 193, 7, 234, 175, 229, 161, 193, 58, 249, 39, 246,
						236, 137, 153, 75, 44, 244, 181, 166, 175, 25, 50, 132,
						165, 175, 24, 198, 54, 226, 245, 17,
					],
					[
						220, 195, 69, 147, 12, 115, 184, 44, 86, 215, 76, 51,
						25, 5, 22, 100, 118, 84, 112, 139, 136, 57, 25, 75, 69,
						84, 44, 155, 218, 134, 155, 28,
					],
					[
						176, 53, 108, 17, 245, 185, 139, 100, 191, 175, 53, 162,
						205, 6, 161, 72, 63, 46, 93, 74, 210, 12, 45, 6, 116,
						246, 173, 247, 232, 181, 24, 44,
					],
					[
						170, 30, 109, 58, 107, 59, 45, 27, 89, 230, 220, 119,
						196, 86, 170, 63, 139, 9, 191, 33, 151, 134, 165, 42,
						45, 252, 41, 188, 254, 67, 93, 46,
					],
				],
				colHat: [
					[
						166, 0, 195, 226, 56, 7, 141, 5, 168, 114, 82, 60, 155,
						255, 2, 3, 53, 238, 141, 5, 34, 202, 161, 100, 212, 210,
						231, 148, 17, 128, 196, 31,
					],
					[
						166, 48, 124, 75, 32, 129, 141, 77, 89, 2, 124, 6, 136,
						237, 233, 240, 207, 160, 182, 99, 136, 104, 211, 8, 230,
						117, 120, 155, 125, 136, 226, 16,
					],
					[
						18, 131, 50, 208, 70, 54, 254, 52, 185, 253, 136, 223,
						218, 253, 11, 119, 132, 25, 91, 185, 114, 61, 29, 223,
						11, 202, 173, 96, 59, 8, 126, 14,
					],
					[
						76, 3, 218, 76, 91, 57, 87, 238, 52, 248, 169, 69, 19,
						175, 68, 211, 245, 128, 177, 232, 244, 239, 52, 82, 210,
						32, 99, 23, 7, 24, 3, 46,
					],
					[
						22, 66, 216, 116, 192, 118, 254, 62, 59, 104, 90, 76,
						26, 245, 114, 149, 253, 79, 103, 80, 180, 119, 137, 134,
						195, 20, 35, 189, 60, 186, 173, 1,
					],
					[
						112, 148, 131, 102, 96, 96, 237, 28, 175, 193, 201, 14,
						213, 243, 134, 197, 61, 30, 24, 200, 212, 132, 209, 67,
						170, 147, 106, 236, 191, 79, 215, 31,
					],
					[
						247, 6, 52, 214, 128, 202, 59, 189, 116, 125, 203, 129,
						193, 62, 195, 233, 251, 212, 29, 189, 99, 150, 20, 109,
						114, 250, 228, 57, 35, 186, 16, 11,
					],
					[
						225, 118, 87, 119, 22, 238, 178, 26, 173, 156, 98, 71,
						192, 180, 191, 86, 145, 4, 41, 128, 239, 85, 220, 81,
						154, 24, 166, 193, 34, 58, 243, 26,
					],
					[
						147, 213, 98, 195, 183, 183, 219, 197, 14, 121, 203, 86,
						231, 143, 93, 33, 12, 158, 134, 111, 190, 17, 66, 174,
						22, 187, 150, 128, 82, 39, 120, 7,
					],
					[
						208, 81, 17, 239, 92, 198, 206, 221, 139, 222, 105, 167,
						134, 227, 38, 53, 176, 26, 167, 208, 177, 166, 42, 118,
						165, 105, 220, 188, 236, 242, 103, 6,
					],
					[
						168, 165, 111, 26, 204, 251, 66, 60, 112, 22, 138, 111,
						93, 24, 167, 236, 206, 113, 25, 48, 250, 31, 206, 106,
						124, 204, 242, 207, 138, 73, 163, 5,
					],
					[
						215, 14, 99, 24, 63, 152, 128, 216, 9, 199, 215, 75,
						102, 219, 3, 200, 99, 48, 190, 59, 128, 150, 19, 177,
						152, 62, 132, 10, 95, 184, 33, 38,
					],
					[
						135, 73, 123, 113, 122, 1, 26, 92, 211, 24, 45, 231, 45,
						45, 8, 100, 115, 91, 195, 248, 56, 226, 179, 114, 247,
						145, 185, 64, 173, 94, 154, 0,
					],
					[
						93, 151, 246, 143, 6, 243, 0, 2, 127, 53, 178, 71, 84,
						75, 242, 250, 205, 55, 209, 127, 177, 192, 232, 71, 96,
						83, 50, 234, 51, 61, 144, 7,
					],
					[
						142, 1, 138, 60, 241, 89, 215, 22, 176, 141, 182, 19,
						41, 157, 13, 54, 156, 31, 102, 44, 111, 206, 15, 200,
						13, 179, 237, 70, 20, 164, 227, 1,
					],
					[
						29, 243, 156, 76, 212, 162, 99, 108, 248, 165, 212, 188,
						149, 26, 90, 54, 239, 231, 136, 103, 171, 193, 187, 122,
						197, 97, 236, 159, 218, 150, 145, 18,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						234, 172, 196, 193, 71, 92, 153, 38, 53, 176, 198, 20,
						118, 119, 6, 195, 1, 167, 163, 209, 177, 211, 26, 68,
						62, 0, 187, 43, 145, 71, 77, 12,
					],
					[
						21, 185, 204, 126, 241, 46, 117, 113, 67, 46, 197, 219,
						159, 101, 58, 252, 146, 178, 145, 155, 119, 23, 219,
						180, 26, 84, 221, 182, 109, 59, 183, 4,
					],
					[
						156, 195, 103, 77, 219, 96, 123, 213, 129, 219, 215, 86,
						125, 115, 141, 86, 135, 94, 223, 223, 84, 29, 68, 247,
						4, 29, 5, 25, 228, 169, 105, 47,
					],
					[
						174, 71, 177, 188, 17, 45, 90, 193, 239, 176, 206, 184,
						94, 169, 115, 192, 61, 247, 71, 220, 239, 197, 107, 156,
						209, 172, 38, 33, 189, 96, 133, 8,
					],
					[
						179, 160, 152, 201, 103, 197, 41, 58, 153, 73, 62, 158,
						51, 248, 223, 88, 194, 98, 57, 78, 35, 114, 209, 70,
						230, 237, 140, 130, 53, 90, 14, 41,
					],
					[
						179, 230, 5, 78, 223, 0, 188, 2, 203, 136, 233, 5, 158,
						145, 134, 95, 32, 220, 106, 211, 27, 138, 181, 216, 36,
						21, 95, 113, 202, 183, 120, 25,
					],
					[
						20, 174, 65, 178, 86, 185, 23, 95, 47, 244, 18, 153, 34,
						16, 154, 183, 49, 51, 157, 187, 34, 189, 61, 239, 35,
						245, 75, 216, 194, 213, 155, 33,
					],
					[
						170, 54, 121, 116, 174, 179, 204, 228, 120, 222, 215,
						78, 207, 127, 182, 55, 37, 109, 195, 102, 210, 51, 200,
						183, 197, 72, 162, 238, 91, 29, 26, 46,
					],
					[
						234, 6, 142, 67, 196, 42, 179, 17, 62, 143, 237, 32,
						142, 201, 22, 218, 159, 84, 173, 127, 206, 230, 234,
						127, 176, 38, 148, 125, 194, 214, 223, 11,
					],
					[
						130, 167, 0, 203, 239, 62, 30, 101, 160, 107, 48, 119,
						125, 217, 35, 58, 53, 222, 99, 254, 92, 171, 230, 243,
						25, 178, 42, 190, 130, 42, 17, 17,
					],
					[
						221, 223, 251, 231, 73, 103, 10, 224, 65, 177, 126, 136,
						122, 51, 70, 181, 230, 88, 87, 251, 149, 71, 189, 129,
						221, 207, 14, 124, 136, 53, 96, 45,
					],
					[
						173, 92, 46, 237, 248, 156, 100, 171, 21, 46, 3, 110,
						33, 221, 45, 171, 84, 195, 99, 27, 188, 137, 61, 55,
						203, 81, 177, 100, 133, 169, 102, 28,
					],
					[
						160, 59, 71, 150, 209, 67, 14, 74, 238, 128, 51, 83, 6,
						125, 32, 53, 57, 130, 18, 19, 102, 197, 245, 48, 124,
						154, 21, 162, 155, 87, 132, 25,
					],
					[
						20, 221, 129, 248, 168, 201, 10, 106, 245, 143, 11, 40,
						218, 37, 137, 235, 208, 150, 121, 149, 72, 192, 211,
						123, 35, 121, 234, 97, 20, 190, 157, 36,
					],
					[
						224, 52, 212, 15, 249, 202, 15, 32, 180, 136, 56, 231,
						57, 113, 124, 59, 140, 117, 183, 115, 254, 23, 79, 170,
						127, 103, 220, 226, 88, 116, 100, 5,
					],
					[
						218, 131, 210, 53, 141, 57, 162, 57, 138, 237, 55, 165,
						151, 224, 15, 206, 170, 255, 153, 213, 166, 216, 165,
						246, 202, 247, 136, 71, 148, 144, 164, 46,
					],
				],
				colHat: [
					[
						165, 111, 106, 101, 137, 234, 30, 99, 112, 98, 219, 251,
						51, 94, 46, 130, 80, 193, 169, 100, 36, 239, 94, 63,
						213, 55, 47, 129, 225, 158, 140, 3,
					],
					[
						235, 118, 152, 195, 138, 158, 137, 26, 66, 229, 135,
						131, 157, 184, 39, 239, 238, 19, 218, 205, 178, 220,
						123, 49, 186, 14, 86, 212, 228, 31, 72, 31,
					],
					[
						111, 86, 220, 224, 200, 238, 0, 102, 243, 223, 231, 246,
						179, 125, 41, 166, 186, 218, 64, 171, 30, 211, 226, 27,
						223, 111, 239, 20, 206, 82, 135, 11,
					],
					[
						79, 146, 224, 114, 197, 186, 17, 99, 18, 80, 130, 47,
						230, 108, 93, 136, 83, 142, 106, 225, 198, 189, 131, 68,
						112, 131, 12, 18, 57, 31, 175, 31,
					],
					[
						25, 113, 105, 39, 39, 75, 214, 56, 124, 82, 97, 190,
						203, 51, 93, 94, 102, 72, 106, 68, 131, 191, 229, 76,
						216, 177, 43, 112, 170, 27, 167, 36,
					],
					[
						147, 130, 77, 78, 39, 121, 135, 118, 93, 175, 183, 186,
						242, 76, 36, 31, 169, 67, 81, 30, 30, 169, 106, 112,
						134, 101, 217, 27, 90, 192, 79, 43,
					],
					[
						95, 182, 47, 66, 165, 182, 155, 35, 109, 19, 157, 5,
						186, 29, 173, 4, 95, 168, 113, 44, 165, 170, 189, 104,
						194, 167, 234, 174, 110, 24, 129, 22,
					],
					[
						139, 93, 42, 218, 164, 170, 166, 203, 237, 45, 205, 124,
						136, 129, 215, 189, 132, 163, 194, 110, 91, 126, 207,
						85, 41, 189, 73, 90, 211, 143, 104, 18,
					],
					[
						97, 28, 43, 133, 83, 109, 67, 17, 194, 9, 196, 31, 26,
						242, 195, 166, 47, 229, 6, 109, 77, 229, 44, 82, 103,
						12, 212, 92, 208, 44, 227, 43,
					],
					[
						196, 255, 17, 7, 82, 10, 221, 197, 162, 156, 121, 221,
						114, 237, 135, 189, 12, 69, 6, 208, 165, 6, 222, 242, 7,
						30, 255, 212, 84, 45, 93, 44,
					],
					[
						77, 5, 6, 208, 16, 20, 200, 113, 42, 237, 212, 47, 24,
						151, 20, 123, 85, 35, 124, 188, 13, 29, 80, 170, 114,
						244, 139, 178, 131, 118, 27, 35,
					],
					[
						87, 98, 112, 88, 176, 72, 122, 71, 58, 176, 220, 134,
						86, 91, 165, 14, 36, 77, 246, 159, 101, 89, 51, 159,
						242, 214, 254, 239, 226, 178, 62, 30,
					],
					[
						167, 103, 239, 64, 168, 106, 102, 188, 62, 83, 146, 93,
						48, 167, 221, 180, 221, 97, 205, 87, 14, 41, 25, 223,
						61, 12, 11, 42, 225, 110, 1, 47,
					],
					[
						249, 139, 179, 50, 93, 233, 122, 132, 120, 222, 105,
						107, 20, 128, 197, 97, 34, 116, 132, 207, 209, 27, 231,
						166, 47, 74, 8, 95, 59, 16, 54, 12,
					],
					[
						22, 212, 144, 36, 12, 13, 182, 60, 77, 231, 158, 62, 36,
						15, 13, 162, 179, 86, 224, 148, 246, 181, 145, 187, 20,
						90, 206, 62, 239, 226, 189, 38,
					],
					[
						92, 92, 187, 147, 139, 57, 0, 208, 67, 173, 216, 200,
						178, 96, 161, 53, 32, 171, 147, 35, 236, 46, 13, 253,
						17, 188, 171, 237, 210, 87, 132, 38,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						227, 65, 112, 180, 241, 149, 216, 197, 135, 78, 30, 252,
						32, 135, 94, 157, 76, 173, 71, 71, 119, 193, 56, 75,
						116, 242, 162, 21, 63, 99, 218, 4,
					],
					[
						77, 249, 141, 40, 208, 47, 186, 80, 61, 206, 159, 98,
						76, 231, 229, 231, 174, 24, 244, 84, 83, 8, 25, 157, 4,
						117, 182, 6, 121, 67, 227, 4,
					],
					[
						117, 69, 67, 161, 112, 115, 149, 74, 213, 72, 13, 130,
						79, 126, 236, 251, 52, 161, 60, 244, 210, 239, 206, 60,
						142, 254, 222, 62, 59, 52, 41, 13,
					],
					[
						111, 58, 92, 119, 50, 117, 93, 233, 109, 91, 95, 187,
						54, 231, 102, 90, 65, 19, 248, 97, 36, 26, 141, 182, 48,
						239, 222, 55, 4, 53, 35, 35,
					],
					[
						92, 2, 39, 64, 121, 226, 187, 32, 239, 213, 117, 223,
						145, 26, 80, 179, 147, 181, 161, 167, 48, 108, 127, 142,
						150, 169, 110, 27, 204, 31, 181, 38,
					],
					[
						14, 170, 87, 224, 135, 199, 150, 130, 175, 62, 153, 85,
						148, 215, 39, 145, 3, 223, 0, 206, 11, 240, 215, 80,
						172, 163, 70, 70, 111, 193, 97, 38,
					],
					[
						58, 6, 56, 255, 62, 35, 30, 2, 216, 0, 64, 201, 140,
						253, 88, 114, 79, 74, 27, 9, 176, 106, 245, 78, 74, 203,
						15, 171, 244, 119, 159, 9,
					],
					[
						243, 112, 25, 193, 214, 233, 184, 61, 60, 24, 194, 49,
						133, 3, 213, 78, 184, 171, 192, 127, 211, 82, 42, 130,
						100, 159, 131, 35, 255, 169, 158, 46,
					],
					[
						4, 31, 206, 160, 191, 218, 138, 4, 9, 120, 18, 152, 167,
						179, 162, 43, 192, 137, 238, 182, 231, 165, 75, 115, 92,
						136, 160, 53, 99, 233, 209, 4,
					],
					[
						63, 23, 107, 29, 58, 185, 77, 206, 170, 220, 216, 232,
						221, 47, 37, 170, 253, 90, 156, 135, 223, 101, 63, 52,
						9, 63, 86, 180, 70, 23, 111, 30,
					],
					[
						186, 15, 25, 3, 96, 153, 9, 241, 31, 172, 226, 88, 94,
						149, 24, 156, 0, 118, 236, 23, 64, 47, 106, 220, 198,
						39, 25, 211, 114, 118, 156, 19,
					],
					[
						54, 135, 189, 65, 5, 200, 9, 60, 221, 48, 157, 99, 44,
						47, 9, 59, 220, 219, 65, 116, 209, 27, 135, 61, 56, 104,
						46, 142, 203, 82, 173, 31,
					],
					[
						40, 35, 118, 142, 119, 96, 192, 197, 148, 245, 99, 163,
						187, 124, 30, 175, 5, 176, 197, 146, 206, 5, 83, 40,
						208, 174, 187, 69, 79, 166, 208, 15,
					],
					[
						230, 144, 234, 135, 190, 227, 207, 153, 127, 133, 185,
						123, 29, 92, 219, 243, 92, 204, 211, 155, 92, 1, 54,
						222, 172, 208, 67, 189, 85, 240, 201, 11,
					],
					[
						210, 127, 87, 46, 114, 72, 130, 114, 215, 133, 9, 94,
						53, 138, 151, 139, 92, 214, 219, 44, 123, 251, 170, 126,
						71, 144, 81, 129, 177, 229, 149, 27,
					],
					[
						105, 26, 172, 203, 164, 196, 146, 74, 232, 197, 108, 60,
						170, 248, 203, 23, 122, 172, 132, 139, 219, 41, 224,
						151, 196, 73, 204, 115, 92, 37, 255, 37,
					],
				],
				colHat: [
					[
						13, 157, 53, 216, 226, 58, 91, 114, 96, 12, 124, 70, 15,
						76, 135, 248, 186, 123, 44, 242, 55, 210, 242, 124, 158,
						202, 140, 223, 176, 243, 139, 26,
					],
					[
						14, 90, 4, 203, 205, 43, 47, 18, 80, 112, 105, 98, 23,
						152, 104, 110, 219, 187, 132, 46, 103, 210, 70, 138,
						234, 208, 205, 97, 31, 58, 249, 9,
					],
					[
						40, 217, 239, 32, 223, 145, 111, 144, 127, 33, 189, 36,
						194, 77, 168, 75, 82, 144, 183, 232, 70, 179, 74, 54,
						93, 101, 219, 77, 67, 48, 197, 46,
					],
					[
						47, 168, 108, 175, 103, 174, 175, 89, 14, 157, 247, 231,
						100, 242, 9, 211, 186, 242, 90, 85, 71, 166, 10, 204, 0,
						92, 182, 26, 112, 170, 118, 31,
					],
					[
						106, 118, 76, 62, 100, 113, 21, 68, 8, 252, 29, 62, 89,
						33, 246, 207, 19, 151, 167, 108, 85, 112, 246, 92, 58,
						217, 229, 28, 46, 17, 34, 36,
					],
					[
						207, 83, 35, 182, 74, 66, 156, 21, 229, 175, 45, 253,
						77, 239, 223, 174, 120, 22, 79, 169, 165, 179, 12, 1,
						193, 145, 231, 87, 78, 44, 52, 28,
					],
					[
						185, 185, 39, 36, 186, 132, 3, 118, 1, 111, 49, 140,
						242, 216, 239, 77, 38, 76, 137, 31, 151, 216, 183, 37,
						222, 240, 125, 119, 156, 44, 103, 3,
					],
					[
						106, 255, 100, 65, 129, 232, 167, 233, 140, 225, 62, 48,
						72, 218, 36, 45, 10, 253, 236, 124, 65, 40, 63, 140,
						107, 104, 0, 112, 241, 219, 74, 4,
					],
					[
						201, 92, 13, 98, 147, 58, 166, 182, 182, 194, 77, 188,
						118, 58, 201, 68, 238, 138, 83, 52, 205, 194, 204, 199,
						198, 193, 44, 167, 168, 167, 50, 12,
					],
					[
						18, 109, 160, 62, 34, 45, 117, 20, 198, 237, 115, 193,
						107, 159, 200, 222, 0, 245, 54, 101, 242, 22, 59, 75,
						66, 177, 217, 198, 17, 35, 194, 11,
					],
					[
						196, 91, 95, 16, 111, 180, 152, 167, 122, 254, 135, 121,
						131, 89, 184, 53, 141, 49, 242, 168, 164, 54, 159, 35,
						209, 49, 118, 214, 106, 33, 3, 43,
					],
					[
						189, 161, 21, 51, 254, 218, 238, 136, 235, 134, 138, 73,
						153, 174, 163, 138, 98, 170, 146, 24, 152, 230, 182,
						205, 124, 187, 160, 226, 231, 123, 167, 34,
					],
					[
						211, 105, 188, 0, 240, 176, 230, 47, 109, 87, 183, 236,
						182, 104, 107, 1, 226, 77, 31, 230, 49, 139, 51, 42, 12,
						91, 43, 3, 52, 29, 2, 21,
					],
					[
						37, 19, 147, 230, 228, 41, 90, 29, 215, 73, 129, 50,
						167, 149, 189, 244, 25, 36, 9, 232, 60, 172, 223, 151,
						29, 180, 195, 255, 17, 191, 45, 4,
					],
					[
						122, 246, 53, 246, 221, 117, 202, 42, 225, 94, 251, 82,
						137, 230, 246, 64, 132, 129, 51, 78, 159, 190, 122, 59,
						19, 190, 205, 147, 55, 121, 114, 44,
					],
					[
						209, 245, 150, 146, 139, 131, 8, 175, 85, 145, 2, 194,
						85, 214, 140, 249, 75, 11, 244, 217, 112, 18, 113, 146,
						219, 113, 20, 65, 88, 34, 22, 19,
					],
				],
			},
			{
				row: [
					[
						91, 15, 70, 208, 5, 182, 57, 182, 151, 156, 199, 228,
						101, 147, 206, 203, 134, 47, 84, 10, 30, 179, 110, 185,
						133, 145, 82, 177, 17, 34, 22, 8,
					],
					[
						12, 254, 181, 202, 92, 222, 255, 75, 219, 199, 43, 116,
						74, 247, 149, 190, 79, 12, 184, 217, 150, 198, 248, 118,
						31, 35, 162, 69, 121, 255, 118, 25,
					],
					[
						16, 126, 252, 185, 27, 150, 206, 132, 160, 216, 122,
						170, 231, 181, 146, 227, 2, 103, 135, 115, 79, 180, 140,
						234, 175, 191, 172, 133, 210, 107, 187, 16,
					],
					[
						15, 114, 161, 118, 95, 96, 100, 113, 21, 158, 155, 125,
						252, 173, 32, 49, 61, 139, 224, 83, 5, 209, 231, 49, 12,
						156, 189, 151, 32, 228, 128, 46,
					],
					[
						141, 200, 159, 179, 227, 159, 26, 51, 218, 200, 16, 190,
						89, 34, 78, 57, 81, 82, 212, 221, 150, 96, 237, 94, 82,
						41, 223, 97, 74, 124, 36, 42,
					],
					[
						107, 154, 150, 187, 176, 78, 151, 42, 89, 216, 48, 2,
						142, 68, 52, 125, 150, 243, 23, 241, 75, 181, 63, 141,
						218, 81, 107, 79, 245, 120, 28, 33,
					],
					[
						252, 219, 100, 54, 103, 230, 187, 142, 66, 43, 149, 246,
						11, 138, 126, 148, 22, 36, 121, 110, 255, 79, 97, 130,
						215, 96, 44, 92, 60, 21, 46, 47,
					],
					[
						13, 158, 199, 36, 242, 118, 174, 31, 97, 2, 96, 61, 208,
						84, 80, 145, 75, 161, 50, 86, 43, 45, 111, 62, 34, 97,
						85, 190, 40, 188, 123, 46,
					],
					[
						129, 91, 71, 112, 6, 240, 192, 147, 120, 129, 216, 158,
						73, 145, 196, 2, 253, 200, 102, 147, 106, 174, 144, 225,
						155, 85, 49, 19, 95, 168, 102, 23,
					],
					[
						136, 209, 19, 254, 130, 162, 147, 162, 245, 37, 143, 57,
						227, 46, 238, 216, 142, 149, 244, 231, 145, 68, 3, 93,
						17, 191, 18, 67, 117, 79, 140, 31,
					],
					[
						3, 97, 207, 199, 40, 239, 46, 140, 11, 52, 180, 247,
						117, 44, 33, 116, 224, 45, 101, 0, 93, 98, 77, 121, 195,
						107, 51, 7, 79, 133, 26, 4,
					],
					[
						91, 97, 176, 123, 215, 14, 243, 179, 117, 55, 122, 181,
						189, 225, 142, 183, 72, 19, 187, 237, 147, 86, 42, 128,
						137, 217, 26, 61, 174, 187, 23, 14,
					],
					[
						56, 116, 103, 65, 152, 58, 67, 169, 101, 92, 49, 228,
						216, 121, 49, 219, 164, 32, 195, 108, 143, 188, 174,
						101, 222, 193, 19, 173, 197, 249, 131, 10,
					],
					[
						110, 93, 22, 93, 180, 192, 232, 184, 3, 118, 32, 110,
						216, 197, 190, 27, 16, 6, 9, 101, 114, 244, 203, 41, 71,
						183, 89, 0, 238, 219, 234, 34,
					],
					[
						206, 22, 93, 214, 77, 89, 62, 203, 125, 180, 14, 93,
						215, 39, 72, 216, 137, 78, 173, 31, 236, 58, 148, 102,
						197, 99, 230, 29, 151, 127, 14, 32,
					],
					[
						45, 219, 7, 118, 182, 206, 96, 190, 245, 67, 249, 90,
						246, 175, 169, 81, 253, 116, 129, 217, 90, 254, 88, 186,
						22, 194, 3, 180, 239, 238, 101, 43,
					],
					[
						108, 218, 132, 92, 214, 146, 118, 252, 21, 250, 226,
						241, 206, 93, 88, 85, 95, 81, 88, 202, 78, 90, 110, 109,
						138, 45, 17, 163, 173, 157, 2, 6,
					],
				],
				colHat: [
					[
						153, 29, 12, 139, 86, 241, 82, 44, 38, 78, 29, 158, 170,
						207, 250, 132, 244, 99, 190, 226, 47, 99, 228, 175, 87,
						253, 80, 70, 91, 151, 81, 8,
					],
					[
						246, 241, 212, 95, 177, 1, 5, 208, 184, 137, 89, 155,
						28, 132, 163, 160, 123, 115, 68, 102, 247, 210, 158,
						196, 144, 132, 231, 12, 166, 253, 243, 3,
					],
					[
						36, 207, 205, 101, 188, 2, 238, 207, 250, 202, 229, 22,
						73, 122, 236, 225, 2, 169, 235, 105, 82, 156, 34, 178,
						70, 115, 132, 95, 69, 33, 247, 45,
					],
					[
						63, 210, 249, 12, 11, 114, 101, 232, 2, 31, 86, 153, 45,
						15, 225, 9, 72, 94, 209, 137, 218, 254, 252, 4, 108,
						248, 177, 209, 254, 41, 255, 45,
					],
					[
						173, 155, 148, 129, 87, 89, 76, 165, 208, 7, 114, 47,
						61, 54, 1, 210, 86, 128, 132, 23, 5, 67, 253, 33, 79,
						116, 39, 203, 84, 228, 31, 27,
					],
					[
						162, 217, 216, 72, 171, 107, 124, 223, 124, 48, 145,
						173, 116, 232, 219, 170, 50, 234, 94, 18, 130, 50, 243,
						240, 189, 189, 92, 154, 219, 93, 192, 6,
					],
					[
						178, 123, 43, 22, 97, 171, 97, 221, 162, 95, 158, 154,
						4, 203, 58, 150, 149, 75, 26, 116, 212, 89, 22, 227,
						123, 159, 191, 92, 203, 240, 164, 37,
					],
					[
						247, 215, 253, 95, 140, 64, 18, 139, 115, 131, 66, 109,
						22, 157, 176, 125, 248, 218, 55, 21, 18, 144, 142, 207,
						228, 199, 255, 80, 99, 62, 102, 37,
					],
					[
						92, 186, 101, 56, 61, 114, 203, 31, 193, 80, 166, 69,
						36, 147, 130, 46, 106, 168, 42, 215, 72, 116, 238, 104,
						96, 5, 124, 60, 175, 217, 76, 2,
					],
					[
						148, 150, 109, 81, 236, 187, 19, 252, 187, 28, 86, 2,
						156, 199, 146, 228, 34, 125, 177, 224, 29, 216, 167, 84,
						183, 244, 245, 155, 20, 188, 173, 18,
					],
					[
						222, 168, 79, 165, 66, 14, 81, 11, 222, 43, 150, 14,
						111, 247, 222, 255, 78, 59, 217, 104, 90, 98, 192, 212,
						243, 90, 192, 206, 39, 205, 109, 46,
					],
					[
						87, 238, 7, 224, 128, 144, 227, 245, 102, 31, 43, 99,
						57, 36, 207, 9, 238, 193, 174, 217, 235, 79, 16, 214,
						125, 213, 69, 51, 217, 135, 39, 7,
					],
					[
						166, 141, 243, 161, 163, 189, 139, 15, 48, 217, 54, 159,
						219, 58, 62, 250, 46, 177, 49, 90, 199, 67, 66, 35, 109,
						198, 237, 124, 188, 167, 16, 46,
					],
					[
						204, 25, 64, 145, 150, 120, 212, 217, 176, 61, 151, 103,
						96, 21, 253, 246, 241, 151, 18, 41, 167, 13, 217, 136,
						94, 250, 82, 153, 123, 28, 19, 6,
					],
					[
						153, 247, 93, 78, 194, 63, 75, 2, 116, 172, 22, 85, 53,
						255, 132, 35, 74, 116, 211, 75, 159, 132, 150, 195, 53,
						107, 153, 1, 111, 68, 206, 38,
					],
					[
						139, 222, 163, 8, 50, 10, 125, 204, 28, 165, 242, 81,
						229, 123, 169, 39, 156, 102, 4, 244, 4, 75, 33, 144, 91,
						150, 51, 236, 232, 194, 199, 22,
					],
				],
			},
		],
	},
};

/*
    Copyright 2021 0kims association.

    This file is part of snarkjs.

    snarkjs is a free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License as published by the
    Free Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    snarkjs is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    snarkjs. If not, see <https://www.gnu.org/licenses/>.
*/
const { stringifyBigInts } = ffjavascript.utils;
async function plonk16Prove(
	zkeyFileName,
	witnessFileName,
	logger
) {
	const { fd: fdWtns, sections: sectionsWtns } =
		await binFileUtils__namespace.readBinFile(
			witnessFileName,
			"wtns",
			2,
			1 << 25,
			1 << 23
		);

	const wtns = await readHeader(fdWtns, sectionsWtns);

	const { fd: fdZKey, sections: sectionsZKey } =
		await binFileUtils__namespace.readBinFile(
			zkeyFileName,
			"zkey",
			2,
			1 << 25,
			1 << 23
		);

	const zkey = await readHeader$1(fdZKey, sectionsZKey);
	if (zkey.protocol != "plonk") {
		throw new Error("zkey file is not plonk");
	}

	if (!ffjavascript.Scalar.eq(zkey.r, wtns.q)) {
		throw new Error(
			"Curve of the witness does not match the curve of the proving key"
		);
	}

	if (wtns.nWitness != zkey.nVars - zkey.nAdditions) {
		throw new Error(
			`Invalid witness length. Circuit: ${zkey.nVars}, witness: ${wtns.nWitness}, ${zkey.nAdditions}`
		);
	}

	const curve = zkey.curve;
	const Fr = curve.Fr;
	const G1 = curve.G1;
	const n8r = curve.Fr.n8;

	if (logger) logger.debug("Reading Wtns");
	const buffWitness = await binFileUtils__namespace.readSection(fdWtns, sectionsWtns, 2);
	// First element in plonk is not used and can be any value. (But always the same).
	// We set it to zero to go faster in the exponentiations.
	buffWitness.set(Fr.zero, 0);
	const buffInternalWitness = new ffjavascript.BigBuffer(n8r * zkey.nAdditions);

	await calculateAdditions();

	let A, B, C, Z;
	let A4, B4, C4, Z4;
	let pol_a, pol_b, pol_c, pol_z, pol_t, pol_r;
	let proof = {};

	const sigmaBuff = new ffjavascript.BigBuffer(zkey.domainSize * n8r * 4 * 3);
	let o = sectionsZKey[12][0].p + zkey.domainSize * n8r;
	await fdZKey.readToBuffer(sigmaBuff, 0, zkey.domainSize * n8r * 4, o);
	o += zkey.domainSize * n8r * 5;
	await fdZKey.readToBuffer(
		sigmaBuff,
		zkey.domainSize * n8r * 4,
		zkey.domainSize * n8r * 4,
		o
	);
	o += zkey.domainSize * n8r * 5;
	await fdZKey.readToBuffer(
		sigmaBuff,
		zkey.domainSize * n8r * 8,
		zkey.domainSize * n8r * 4,
		o
	);

	const pol_s1 = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
	await fdZKey.readToBuffer(
		pol_s1,
		0,
		zkey.domainSize * n8r,
		sectionsZKey[12][0].p
	);

	const pol_s2 = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
	await fdZKey.readToBuffer(
		pol_s2,
		0,
		zkey.domainSize * n8r,
		sectionsZKey[12][0].p + 5 * zkey.domainSize * n8r
	);

	const PTau = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 14);

	const ch = {};

	// instantiate Transcript
	let transcript = new Transcript(poseidon_spec, curve);
	transcript.load();

	await round1();
	await round2();
	await round3();
	await round4();
	await round5();

	///////////////////////
	// Final adjustments //
	///////////////////////

	proof.protocol = "plonk";
	proof.curve = curve.name;

	await fdZKey.close();
	await fdWtns.close();

	let publicSignals = [];

	for (let i = 1; i <= zkey.nPublic; i++) {
		const pub = buffWitness.slice(i * Fr.n8, i * Fr.n8 + Fr.n8);
		publicSignals.push(ffjavascript.Scalar.fromRprLE(pub));
	}

	proof.A = G1.toObject(proof.A);
	proof.B = G1.toObject(proof.B);
	proof.C = G1.toObject(proof.C);
	proof.Z = G1.toObject(proof.Z);

	proof.T1 = G1.toObject(proof.T1);
	proof.T2 = G1.toObject(proof.T2);
	proof.T3 = G1.toObject(proof.T3);

	proof.eval_a = Fr.toObject(proof.eval_a);
	proof.eval_b = Fr.toObject(proof.eval_b);
	proof.eval_c = Fr.toObject(proof.eval_c);
	proof.eval_s1 = Fr.toObject(proof.eval_s1);
	proof.eval_s2 = Fr.toObject(proof.eval_s2);
	proof.eval_zw = Fr.toObject(proof.eval_zw);
	proof.eval_t = Fr.toObject(proof.eval_t);
	proof.eval_r = Fr.toObject(proof.eval_r);

	proof.Wxi = G1.toObject(proof.Wxi);
	proof.Wxiw = G1.toObject(proof.Wxiw);

	delete proof.eval_t;

	proof = stringifyBigInts(proof);
	publicSignals = stringifyBigInts(publicSignals);

	return { proof, publicSignals };

	async function calculateAdditions() {
		const additionsBuff = await binFileUtils__namespace.readSection(
			fdZKey,
			sectionsZKey,
			3
		);

		const sSum = 8 + curve.Fr.n8 * 2;

		for (let i = 0; i < zkey.nAdditions; i++) {
			const ai = readUInt32(additionsBuff, i * sSum);
			const bi = readUInt32(additionsBuff, i * sSum + 4);
			const ac = additionsBuff.slice(i * sSum + 8, i * sSum + 8 + n8r);
			const bc = additionsBuff.slice(
				i * sSum + 8 + n8r,
				i * sSum + 8 + n8r * 2
			);
			const aw = getWitness(ai);
			const bw = getWitness(bi);

			const r = curve.Fr.add(curve.Fr.mul(ac, aw), curve.Fr.mul(bc, bw));
			buffInternalWitness.set(r, n8r * i);
		}
	}

	async function buildABC() {
		let A = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
		let B = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
		let C = new ffjavascript.BigBuffer(zkey.domainSize * n8r);

		const aMap = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 4);
		const bMap = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 5);
		const cMap = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 6);

		for (let i = 0; i < zkey.nConstrains; i++) {
			const iA = readUInt32(aMap, i * 4);
			A.set(getWitness(iA), i * n8r);
			const iB = readUInt32(bMap, i * 4);
			B.set(getWitness(iB), i * n8r);
			const iC = readUInt32(cMap, i * 4);
			C.set(getWitness(iC), i * n8r);
		}

		A = await Fr.batchToMontgomery(A);
		B = await Fr.batchToMontgomery(B);
		C = await Fr.batchToMontgomery(C);

		return [A, B, C];
	}

	function readUInt32(b, o) {
		const buff = b.slice(o, o + 4);
		const buffV = new DataView(
			buff.buffer,
			buff.byteOffset,
			buff.byteLength
		);
		return buffV.getUint32(0, true);
	}

	function getWitness(idx) {
		if (idx < zkey.nVars - zkey.nAdditions) {
			return buffWitness.slice(idx * n8r, idx * n8r + n8r);
		} else if (idx < zkey.nVars) {
			return buffInternalWitness.slice(
				(idx - (zkey.nVars - zkey.nAdditions)) * n8r,
				(idx - (zkey.nVars - zkey.nAdditions)) * n8r + n8r
			);
		} else {
			return curve.Fr.zero;
		}
	}

	async function round1() {
		ch.b = [];
		for (let i = 1; i <= 11; i++) {
			ch.b[i] = curve.Fr.random();
		}

		[A, B, C] = await buildABC();

		[pol_a, A4] = await to4T(A, [ch.b[2], ch.b[1]]);
		[pol_b, B4] = await to4T(B, [ch.b[4], ch.b[3]]);
		[pol_c, C4] = await to4T(C, [ch.b[6], ch.b[5]]);

		proof.A = await expTau(pol_a, "multiexp A");
		proof.B = await expTau(pol_b, "multiexp B");
		proof.C = await expTau(pol_c, "multiexp C");
	}

	async function round2() {
		// const transcript1 = new Uint8Array(
		// 	zkey.nPublic * n8r + G1.F.n8 * 2 * 3
		// );

		for (let i = 0; i < zkey.nPublic; i++) {
			transcript.writeScalar(A.slice(i * n8r, (i + 1) * n8r), `pi ${i}`);
			// Fr.toRprBE(transcript1, i * n8r, A.slice(i * n8r, (i + 1) * n8r));
		}

		transcript.writePoint(proof.A, "A");
		transcript.writePoint(proof.B, "B");
		transcript.writePoint(proof.C, "C");

		// G1.toRprUncompressed(transcript1, zkey.nPublic * n8r + 0, proof.A);
		// G1.toRprUncompressed(
		// 	transcript1,
		// 	zkey.nPublic * n8r + G1.F.n8 * 2,
		// 	proof.B
		// );
		// G1.toRprUncompressed(
		// 	transcript1,
		// 	zkey.nPublic * n8r + G1.F.n8 * 4,
		// 	proof.C
		// );

		ch.beta = transcript.squeezeChallenge();
		if (logger) logger.debug("beta: " + Fr.toString(ch.beta));

		// const transcript2 = new Uint8Array(n8r);
		// Fr.toRprBE(transcript2, 0, ch.beta);
		transcript.writeScalar(ch.beta, "beta");
		ch.gamma = transcript.squeezeChallenge();
		if (logger) logger.debug("gamma: " + Fr.toString(ch.gamma));

		let numArr = new ffjavascript.BigBuffer(Fr.n8 * zkey.domainSize);
		let denArr = new ffjavascript.BigBuffer(Fr.n8 * zkey.domainSize);

		numArr.set(Fr.one, 0);
		denArr.set(Fr.one, 0);

		let w = Fr.one;
		for (let i = 0; i < zkey.domainSize; i++) {
			let n1 = A.slice(i * n8r, (i + 1) * n8r);
			n1 = Fr.add(n1, Fr.mul(ch.beta, w));
			n1 = Fr.add(n1, ch.gamma);

			let n2 = B.slice(i * n8r, (i + 1) * n8r);
			n2 = Fr.add(n2, Fr.mul(zkey.k1, Fr.mul(ch.beta, w)));
			n2 = Fr.add(n2, ch.gamma);

			let n3 = C.slice(i * n8r, (i + 1) * n8r);
			n3 = Fr.add(n3, Fr.mul(zkey.k2, Fr.mul(ch.beta, w)));
			n3 = Fr.add(n3, ch.gamma);

			const num = Fr.mul(n1, Fr.mul(n2, n3));

			let d1 = A.slice(i * n8r, (i + 1) * n8r);
			d1 = Fr.add(
				d1,
				Fr.mul(sigmaBuff.slice(i * n8r * 4, i * n8r * 4 + n8r), ch.beta)
			);
			d1 = Fr.add(d1, ch.gamma);

			let d2 = B.slice(i * n8r, (i + 1) * n8r);
			d2 = Fr.add(
				d2,
				Fr.mul(
					sigmaBuff.slice(
						(zkey.domainSize + i) * 4 * n8r,
						(zkey.domainSize + i) * 4 * n8r + n8r
					),
					ch.beta
				)
			);
			d2 = Fr.add(d2, ch.gamma);

			let d3 = C.slice(i * n8r, (i + 1) * n8r);
			d3 = Fr.add(
				d3,
				Fr.mul(
					sigmaBuff.slice(
						(zkey.domainSize * 2 + i) * 4 * n8r,
						(zkey.domainSize * 2 + i) * 4 * n8r + n8r
					),
					ch.beta
				)
			);
			d3 = Fr.add(d3, ch.gamma);

			const den = Fr.mul(d1, Fr.mul(d2, d3));

			numArr.set(
				Fr.mul(numArr.slice(i * n8r, (i + 1) * n8r), num),
				((i + 1) % zkey.domainSize) * n8r
			);

			denArr.set(
				Fr.mul(denArr.slice(i * n8r, (i + 1) * n8r), den),
				((i + 1) % zkey.domainSize) * n8r
			);

			w = Fr.mul(w, Fr.w[zkey.power]);
		}

		denArr = await Fr.batchInverse(denArr);

		// TODO: Do it in assembly and in parallel
		for (let i = 0; i < zkey.domainSize; i++) {
			numArr.set(
				Fr.mul(
					numArr.slice(i * n8r, (i + 1) * n8r),
					denArr.slice(i * n8r, (i + 1) * n8r)
				),
				i * n8r
			);
		}

		if (!Fr.eq(numArr.slice(0, n8r), Fr.one)) {
			throw new Error("Copy constraints does not match");
		}

		Z = numArr;

		[pol_z, Z4] = await to4T(Z, [ch.b[9], ch.b[8], ch.b[7]]);

		proof.Z = await expTau(pol_z, "multiexp Z");
	}

	async function round3() {
		/*
        async function checkDegree(P) {
            const p = await curve.Fr.ifft(P);
            let deg = (P.byteLength/n8r)-1;
            while ((deg>0)&&(Fr.isZero(p.slice(deg*n8r, deg*n8r+n8r)))) deg--;
            return deg;
        }

        function printPol(P) {
            const n=(P.byteLength/n8r);
            console.log("[");
            for (let i=0; i<n; i++) {
                console.log(Fr.toString(P.slice(i*n8r, i*n8r+n8r)));
            }
            console.log("]");
        }
        */

		if (logger) logger.debug("phse3: Reading QM4");
		const QM4 = new ffjavascript.BigBuffer(zkey.domainSize * 4 * n8r);
		await fdZKey.readToBuffer(
			QM4,
			0,
			zkey.domainSize * n8r * 4,
			sectionsZKey[7][0].p + zkey.domainSize * n8r
		);

		if (logger) logger.debug("phse3: Reading QL4");
		const QL4 = new ffjavascript.BigBuffer(zkey.domainSize * 4 * n8r);
		await fdZKey.readToBuffer(
			QL4,
			0,
			zkey.domainSize * n8r * 4,
			sectionsZKey[8][0].p + zkey.domainSize * n8r
		);

		if (logger) logger.debug("phse3: Reading QR4");
		const QR4 = new ffjavascript.BigBuffer(zkey.domainSize * 4 * n8r);
		await fdZKey.readToBuffer(
			QR4,
			0,
			zkey.domainSize * n8r * 4,
			sectionsZKey[9][0].p + zkey.domainSize * n8r
		);

		if (logger) logger.debug("phse3: Reading QO4");
		const QO4 = new ffjavascript.BigBuffer(zkey.domainSize * 4 * n8r);
		await fdZKey.readToBuffer(
			QO4,
			0,
			zkey.domainSize * n8r * 4,
			sectionsZKey[10][0].p + zkey.domainSize * n8r
		);

		if (logger) logger.debug("phse3: Reading QC4");
		const QC4 = new ffjavascript.BigBuffer(zkey.domainSize * 4 * n8r);
		await fdZKey.readToBuffer(
			QC4,
			0,
			zkey.domainSize * n8r * 4,
			sectionsZKey[11][0].p + zkey.domainSize * n8r
		);

		const lPols = await binFileUtils__namespace.readSection(fdZKey, sectionsZKey, 13);

		// const transcript3 = new Uint8Array(G1.F.n8 * 2);
		// G1.toRprUncompressed(transcript3, 0, proof.Z);
		transcript.writePoint(proof.Z, "Z");

		ch.alpha = transcript.squeezeChallenge();

		if (logger) logger.debug("alpha: " + Fr.toString(ch.alpha));

		const Z1 = [
			Fr.zero,
			Fr.add(Fr.e(-1), Fr.w[2]),
			Fr.e(-2),
			Fr.sub(Fr.e(-1), Fr.w[2]),
		];

		const Z2 = [
			Fr.zero,
			Fr.add(Fr.zero, Fr.mul(Fr.e(-2), Fr.w[2])),
			Fr.e(4),
			Fr.sub(Fr.zero, Fr.mul(Fr.e(-2), Fr.w[2])),
		];

		const Z3 = [
			Fr.zero,
			Fr.add(Fr.e(2), Fr.mul(Fr.e(2), Fr.w[2])),
			Fr.e(-8),
			Fr.sub(Fr.e(2), Fr.mul(Fr.e(2), Fr.w[2])),
		];

		const T = new ffjavascript.BigBuffer(zkey.domainSize * 4 * n8r);
		const Tz = new ffjavascript.BigBuffer(zkey.domainSize * 4 * n8r);

		let w = Fr.one;
		for (let i = 0; i < zkey.domainSize * 4; i++) {
			if (i % 4096 == 0 && logger)
				logger.debug(`calculating t ${i}/${zkey.domainSize * 4}`);

			const a = A4.slice(i * n8r, i * n8r + n8r);
			const b = B4.slice(i * n8r, i * n8r + n8r);
			const c = C4.slice(i * n8r, i * n8r + n8r);
			const z = Z4.slice(i * n8r, i * n8r + n8r);
			const zw = Z4.slice(
				((i + zkey.domainSize * 4 + 4) % (zkey.domainSize * 4)) * n8r,
				((i + zkey.domainSize * 4 + 4) % (zkey.domainSize * 4)) * n8r +
					n8r
			);
			const qm = QM4.slice(i * n8r, i * n8r + n8r);
			const ql = QL4.slice(i * n8r, i * n8r + n8r);
			const qr = QR4.slice(i * n8r, i * n8r + n8r);
			const qo = QO4.slice(i * n8r, i * n8r + n8r);
			const qc = QC4.slice(i * n8r, i * n8r + n8r);
			const s1 = sigmaBuff.slice(i * n8r, i * n8r + n8r);
			const s2 = sigmaBuff.slice(
				(i + zkey.domainSize * 4) * n8r,
				(i + zkey.domainSize * 4) * n8r + n8r
			);
			const s3 = sigmaBuff.slice(
				(i + zkey.domainSize * 8) * n8r,
				(i + zkey.domainSize * 8) * n8r + n8r
			);
			const ap = Fr.add(ch.b[2], Fr.mul(ch.b[1], w));
			const bp = Fr.add(ch.b[4], Fr.mul(ch.b[3], w));
			const cp = Fr.add(ch.b[6], Fr.mul(ch.b[5], w));
			const w2 = Fr.square(w);
			const zp = Fr.add(
				Fr.add(Fr.mul(ch.b[7], w2), Fr.mul(ch.b[8], w)),
				ch.b[9]
			);
			const wW = Fr.mul(w, Fr.w[zkey.power]);
			const wW2 = Fr.square(wW);
			const zWp = Fr.add(
				Fr.add(Fr.mul(ch.b[7], wW2), Fr.mul(ch.b[8], wW)),
				ch.b[9]
			);

			let pl = Fr.zero;
			for (let j = 0; j < zkey.nPublic; j++) {
				pl = Fr.sub(
					pl,
					Fr.mul(
						lPols.slice(
							(j * 5 * zkey.domainSize + zkey.domainSize + i) *
								n8r,
							(j * 5 * zkey.domainSize +
								zkey.domainSize +
								i +
								1) *
								n8r
						),
						A.slice(j * n8r, (j + 1) * n8r)
					)
				);
			}

			let [e1, e1z] = mul2(a, b, ap, bp, i % 4);
			e1 = Fr.mul(e1, qm);
			e1z = Fr.mul(e1z, qm);

			e1 = Fr.add(e1, Fr.mul(a, ql));
			e1z = Fr.add(e1z, Fr.mul(ap, ql));

			e1 = Fr.add(e1, Fr.mul(b, qr));
			e1z = Fr.add(e1z, Fr.mul(bp, qr));

			e1 = Fr.add(e1, Fr.mul(c, qo));
			e1z = Fr.add(e1z, Fr.mul(cp, qo));

			e1 = Fr.add(e1, pl);
			e1 = Fr.add(e1, qc);

			const betaw = Fr.mul(ch.beta, w);
			let e2a = a;
			e2a = Fr.add(e2a, betaw);
			e2a = Fr.add(e2a, ch.gamma);

			let e2b = b;
			e2b = Fr.add(e2b, Fr.mul(betaw, zkey.k1));
			e2b = Fr.add(e2b, ch.gamma);

			let e2c = c;
			e2c = Fr.add(e2c, Fr.mul(betaw, zkey.k2));
			e2c = Fr.add(e2c, ch.gamma);

			let e2d = z;

			let [e2, e2z] = mul4(e2a, e2b, e2c, e2d, ap, bp, cp, zp, i % 4);
			e2 = Fr.mul(e2, ch.alpha);
			e2z = Fr.mul(e2z, ch.alpha);

			let e3a = a;
			e3a = Fr.add(e3a, Fr.mul(ch.beta, s1));
			e3a = Fr.add(e3a, ch.gamma);

			let e3b = b;
			e3b = Fr.add(e3b, Fr.mul(ch.beta, s2));
			e3b = Fr.add(e3b, ch.gamma);

			let e3c = c;
			e3c = Fr.add(e3c, Fr.mul(ch.beta, s3));
			e3c = Fr.add(e3c, ch.gamma);

			let e3d = zw;
			let [e3, e3z] = mul4(e3a, e3b, e3c, e3d, ap, bp, cp, zWp, i % 4);

			e3 = Fr.mul(e3, ch.alpha);
			e3z = Fr.mul(e3z, ch.alpha);

			let e4 = Fr.sub(z, Fr.one);
			e4 = Fr.mul(
				e4,
				lPols.slice(
					(zkey.domainSize + i) * n8r,
					(zkey.domainSize + i + 1) * n8r
				)
			);
			e4 = Fr.mul(e4, Fr.mul(ch.alpha, ch.alpha));

			let e4z = Fr.mul(
				zp,
				lPols.slice(
					(zkey.domainSize + i) * n8r,
					(zkey.domainSize + i + 1) * n8r
				)
			);
			e4z = Fr.mul(e4z, Fr.mul(ch.alpha, ch.alpha));

			let e = Fr.add(Fr.sub(Fr.add(e1, e2), e3), e4);
			let ez = Fr.add(Fr.sub(Fr.add(e1z, e2z), e3z), e4z);

			T.set(e, i * n8r);
			Tz.set(ez, i * n8r);

			w = Fr.mul(w, Fr.w[zkey.power + 2]);
		}

		if (logger) logger.debug("ifft T");
		let t = await Fr.ifft(T);

		if (logger) logger.debug("dividing T/Z");
		for (let i = 0; i < zkey.domainSize; i++) {
			t.set(Fr.neg(t.slice(i * n8r, i * n8r + n8r)), i * n8r);
		}

		for (let i = zkey.domainSize; i < zkey.domainSize * 4; i++) {
			const a = Fr.sub(
				t.slice(
					(i - zkey.domainSize) * n8r,
					(i - zkey.domainSize) * n8r + n8r
				),
				t.slice(i * n8r, i * n8r + n8r)
			);
			t.set(a, i * n8r);
			if (i > zkey.domainSize * 3 - 4) {
				if (!Fr.isZero(a)) {
					throw new Error("T Polynomial is not divisible");
				}
			}
		}

		if (logger) logger.debug("ifft Tz");
		const tz = await Fr.ifft(Tz);
		for (let i = 0; i < zkey.domainSize * 4; i++) {
			const a = tz.slice(i * n8r, (i + 1) * n8r);
			if (i > zkey.domainSize * 3 + 5) {
				if (!Fr.isZero(a)) {
					throw new Error("Tz Polynomial is not well calculated");
				}
			} else {
				t.set(Fr.add(t.slice(i * n8r, (i + 1) * n8r), a), i * n8r);
			}
		}

		pol_t = t.slice(0, (zkey.domainSize * 3 + 6) * n8r);

		// t(x) has degree 3n + 5, we are going to split t(x) into three smaller polynomials:
		// t'_low and t'_mid  with a degree < n and t'_high with a degree n+5
		// such that t(x) = t'_low(X) + X^n t'_mid(X) + X^{2n} t'_hi(X)
		// To randomize the parts we use blinding scalars b_10 and b_11 in a way that doesn't change t(X):
		// t_low(X) = t'_low(X) + b_10 X^n
		// t_mid(X) = t'_mid(X) - b_10 + b_11 X^n
		// t_high(X) = t'_high(X) - b_11
		// such that
		// t(X) = t_low(X) + X^n t_mid(X) + X^2n t_high(X)

		// compute t_low(X)
		let polTLow = new ffjavascript.BigBuffer((zkey.domainSize + 1) * n8r);
		polTLow.set(t.slice(0, zkey.domainSize * n8r), 0);
		// Add blinding scalar b_10 as a new coefficient n
		polTLow.set(ch.b[10], zkey.domainSize * n8r);

		// compute t_mid(X)
		let polTMid = new ffjavascript.BigBuffer((zkey.domainSize + 1) * n8r);
		polTMid.set(
			t.slice(zkey.domainSize * n8r, zkey.domainSize * 2 * n8r),
			0
		);
		// Subtract blinding scalar b_10 to the lowest coefficient of t_mid
		const lowestMid = Fr.sub(polTMid.slice(0, n8r), ch.b[10]);
		polTMid.set(lowestMid, 0);
		// Add blinding scalar b_11 as a new coefficient n
		polTMid.set(ch.b[11], zkey.domainSize * n8r);

		// compute t_high(X)
		let polTHigh = new ffjavascript.BigBuffer((zkey.domainSize + 6) * n8r);
		polTHigh.set(
			t.slice(zkey.domainSize * 2 * n8r, (zkey.domainSize * 3 + 6) * n8r),
			0
		);
		//Subtract blinding scalar b_11 to the lowest coefficient of t_high
		const lowestHigh = Fr.sub(polTHigh.slice(0, n8r), ch.b[11]);
		polTHigh.set(lowestHigh, 0);

		proof.T1 = await expTau(polTLow, "multiexp T1");
		proof.T2 = await expTau(polTMid, "multiexp T2");
		proof.T3 = await expTau(polTHigh, "multiexp T3");

		function mul2(a, b, ap, bp, p) {
			let r, rz;

			const a_b = Fr.mul(a, b);
			const a_bp = Fr.mul(a, bp);
			const ap_b = Fr.mul(ap, b);
			const ap_bp = Fr.mul(ap, bp);

			r = a_b;

			let a0 = Fr.add(a_bp, ap_b);

			let a1 = ap_bp;

			rz = a0;
			if (p) {
				rz = Fr.add(rz, Fr.mul(Z1[p], a1));
			}

			return [r, rz];
		}

		function mul4(a, b, c, d, ap, bp, cp, dp, p) {
			let r, rz;

			const a_b = Fr.mul(a, b);
			const a_bp = Fr.mul(a, bp);
			const ap_b = Fr.mul(ap, b);
			const ap_bp = Fr.mul(ap, bp);

			const c_d = Fr.mul(c, d);
			const c_dp = Fr.mul(c, dp);
			const cp_d = Fr.mul(cp, d);
			const cp_dp = Fr.mul(cp, dp);

			r = Fr.mul(a_b, c_d);

			let a0 = Fr.mul(ap_b, c_d);
			a0 = Fr.add(a0, Fr.mul(a_bp, c_d));
			a0 = Fr.add(a0, Fr.mul(a_b, cp_d));
			a0 = Fr.add(a0, Fr.mul(a_b, c_dp));

			let a1 = Fr.mul(ap_bp, c_d);
			a1 = Fr.add(a1, Fr.mul(ap_b, cp_d));
			a1 = Fr.add(a1, Fr.mul(ap_b, c_dp));
			a1 = Fr.add(a1, Fr.mul(a_bp, cp_d));
			a1 = Fr.add(a1, Fr.mul(a_bp, c_dp));
			a1 = Fr.add(a1, Fr.mul(a_b, cp_dp));

			let a2 = Fr.mul(a_bp, cp_dp);
			a2 = Fr.add(a2, Fr.mul(ap_b, cp_dp));
			a2 = Fr.add(a2, Fr.mul(ap_bp, c_dp));
			a2 = Fr.add(a2, Fr.mul(ap_bp, cp_d));

			let a3 = Fr.mul(ap_bp, cp_dp);

			rz = a0;
			if (p) {
				rz = Fr.add(rz, Fr.mul(Z1[p], a1));
				rz = Fr.add(rz, Fr.mul(Z2[p], a2));
				rz = Fr.add(rz, Fr.mul(Z3[p], a3));
			}

			return [r, rz];
		}
	}

	async function round4() {
		const pol_qm = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
		await fdZKey.readToBuffer(
			pol_qm,
			0,
			zkey.domainSize * n8r,
			sectionsZKey[7][0].p
		);

		const pol_ql = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
		await fdZKey.readToBuffer(
			pol_ql,
			0,
			zkey.domainSize * n8r,
			sectionsZKey[8][0].p
		);

		const pol_qr = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
		await fdZKey.readToBuffer(
			pol_qr,
			0,
			zkey.domainSize * n8r,
			sectionsZKey[9][0].p
		);

		const pol_qo = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
		await fdZKey.readToBuffer(
			pol_qo,
			0,
			zkey.domainSize * n8r,
			sectionsZKey[10][0].p
		);

		const pol_qc = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
		await fdZKey.readToBuffer(
			pol_qc,
			0,
			zkey.domainSize * n8r,
			sectionsZKey[11][0].p
		);

		const pol_s3 = new ffjavascript.BigBuffer(zkey.domainSize * n8r);
		await fdZKey.readToBuffer(
			pol_s3,
			0,
			zkey.domainSize * n8r,
			sectionsZKey[12][0].p + 10 * zkey.domainSize * n8r
		);

		transcript.writePoint(proof.T1, "T1");
		transcript.writePoint(proof.T2, "T2");
		transcript.writePoint(proof.T3, "T3");
		// const transcript4 = new Uint8Array(G1.F.n8 * 2 * 3);
		// G1.toRprUncompressed(transcript4, 0, proof.T1);
		// G1.toRprUncompressed(transcript4, G1.F.n8 * 2, proof.T2);
		// G1.toRprUncompressed(transcript4, G1.F.n8 * 4, proof.T3);
		ch.xi = transcript.squeezeChallenge();

		if (logger) logger.debug("xi: " + Fr.toString(ch.xi));

		proof.eval_a = evalPol(pol_a, ch.xi);
		proof.eval_b = evalPol(pol_b, ch.xi);
		proof.eval_c = evalPol(pol_c, ch.xi);
		proof.eval_s1 = evalPol(pol_s1, ch.xi);
		proof.eval_s2 = evalPol(pol_s2, ch.xi);
		proof.eval_t = evalPol(pol_t, ch.xi);
		proof.eval_zw = evalPol(pol_z, Fr.mul(ch.xi, Fr.w[zkey.power]));

		const coef_ab = Fr.mul(proof.eval_a, proof.eval_b);

		let e2a = proof.eval_a;
		const betaxi = Fr.mul(ch.beta, ch.xi);
		e2a = Fr.add(e2a, betaxi);
		e2a = Fr.add(e2a, ch.gamma);

		let e2b = proof.eval_b;
		e2b = Fr.add(e2b, Fr.mul(betaxi, zkey.k1));
		e2b = Fr.add(e2b, ch.gamma);

		let e2c = proof.eval_c;
		e2c = Fr.add(e2c, Fr.mul(betaxi, zkey.k2));
		e2c = Fr.add(e2c, ch.gamma);

		const e2 = Fr.mul(Fr.mul(Fr.mul(e2a, e2b), e2c), ch.alpha);

		let e3a = proof.eval_a;
		e3a = Fr.add(e3a, Fr.mul(ch.beta, proof.eval_s1));
		e3a = Fr.add(e3a, ch.gamma);

		let e3b = proof.eval_b;
		e3b = Fr.add(e3b, Fr.mul(ch.beta, proof.eval_s2));
		e3b = Fr.add(e3b, ch.gamma);

		let e3 = Fr.mul(e3a, e3b);
		e3 = Fr.mul(e3, ch.beta);
		e3 = Fr.mul(e3, proof.eval_zw);
		e3 = Fr.mul(e3, ch.alpha);

		ch.xim = ch.xi;
		for (let i = 0; i < zkey.power; i++) ch.xim = Fr.mul(ch.xim, ch.xim);
		const eval_l1 = Fr.div(
			Fr.sub(ch.xim, Fr.one),
			Fr.mul(Fr.sub(ch.xi, Fr.one), Fr.e(zkey.domainSize))
		);

		const e4 = Fr.mul(eval_l1, Fr.mul(ch.alpha, ch.alpha));

		const coefs3 = e3;
		const coefz = Fr.add(e2, e4);

		pol_r = new ffjavascript.BigBuffer((zkey.domainSize + 3) * n8r);

		for (let i = 0; i < zkey.domainSize + 3; i++) {
			let v = Fr.mul(coefz, pol_z.slice(i * n8r, (i + 1) * n8r));
			if (i < zkey.domainSize) {
				v = Fr.add(
					v,
					Fr.mul(coef_ab, pol_qm.slice(i * n8r, (i + 1) * n8r))
				);
				v = Fr.add(
					v,
					Fr.mul(proof.eval_a, pol_ql.slice(i * n8r, (i + 1) * n8r))
				);
				v = Fr.add(
					v,
					Fr.mul(proof.eval_b, pol_qr.slice(i * n8r, (i + 1) * n8r))
				);
				v = Fr.add(
					v,
					Fr.mul(proof.eval_c, pol_qo.slice(i * n8r, (i + 1) * n8r))
				);
				v = Fr.add(v, pol_qc.slice(i * n8r, (i + 1) * n8r));
				v = Fr.sub(
					v,
					Fr.mul(coefs3, pol_s3.slice(i * n8r, (i + 1) * n8r))
				);
			}
			pol_r.set(v, i * n8r);
		}

		proof.eval_r = evalPol(pol_r, ch.xi);
	}

	async function round5() {
		transcript.writeScalar(proof.eval_a, "eval_a");
		transcript.writeScalar(proof.eval_b, "eval_b");
		transcript.writeScalar(proof.eval_c, "eval_c");
		transcript.writeScalar(proof.eval_s1, "eval_s1");
		transcript.writeScalar(proof.eval_s2, "eval_s2");
		transcript.writeScalar(proof.eval_zw, "eval_zw");
		transcript.writeScalar(proof.eval_r, "eval_r");
		// const transcript5 = new Uint8Array(n8r * 7);
		// Fr.toRprBE(transcript5, 0, proof.eval_a);
		// Fr.toRprBE(transcript5, n8r, proof.eval_b);
		// Fr.toRprBE(transcript5, n8r * 2, proof.eval_c);
		// Fr.toRprBE(transcript5, n8r * 3, proof.eval_s1);
		// Fr.toRprBE(transcript5, n8r * 4, proof.eval_s2);
		// Fr.toRprBE(transcript5, n8r * 5, proof.eval_zw);
		// Fr.toRprBE(transcript5, n8r * 6, proof.eval_r);
		ch.v = [];
		ch.v[1] = transcript.squeezeChallenge();
		if (logger) logger.debug("v: " + Fr.toString(ch.v[1]));

		for (let i = 2; i <= 6; i++) ch.v[i] = Fr.mul(ch.v[i - 1], ch.v[1]);

		let pol_wxi = new ffjavascript.BigBuffer((zkey.domainSize + 6) * n8r);

		const xi2m = Fr.mul(ch.xim, ch.xim);

		for (let i = 0; i < zkey.domainSize + 6; i++) {
			let w = Fr.zero;

			const polTHigh = pol_t.slice(
				(zkey.domainSize * 2 + i) * n8r,
				(zkey.domainSize * 2 + i + 1) * n8r
			);
			w = Fr.add(w, Fr.mul(xi2m, polTHigh));

			if (i < zkey.domainSize + 3) {
				w = Fr.add(
					w,
					Fr.mul(ch.v[1], pol_r.slice(i * n8r, (i + 1) * n8r))
				);
			}

			if (i < zkey.domainSize + 2) {
				w = Fr.add(
					w,
					Fr.mul(ch.v[2], pol_a.slice(i * n8r, (i + 1) * n8r))
				);
				w = Fr.add(
					w,
					Fr.mul(ch.v[3], pol_b.slice(i * n8r, (i + 1) * n8r))
				);
				w = Fr.add(
					w,
					Fr.mul(ch.v[4], pol_c.slice(i * n8r, (i + 1) * n8r))
				);
			}

			if (i < zkey.domainSize) {
				const polTLow = pol_t.slice(i * n8r, (i + 1) * n8r);
				w = Fr.add(w, polTLow);

				const polTMid = pol_t.slice(
					(zkey.domainSize + i) * n8r,
					(zkey.domainSize + i + 1) * n8r
				);
				w = Fr.add(w, Fr.mul(ch.xim, polTMid));

				w = Fr.add(
					w,
					Fr.mul(ch.v[5], pol_s1.slice(i * n8r, (i + 1) * n8r))
				);
				w = Fr.add(
					w,
					Fr.mul(ch.v[6], pol_s2.slice(i * n8r, (i + 1) * n8r))
				);
			}

			// b_10 and b_11 blinding scalars were applied on round 3 to randomize the polynomials t_low, t_mid, t_high
			// Subtract blinding scalar b_10 and b_11 to the lowest coefficient
			if (i === 0) {
				w = Fr.sub(w, Fr.mul(xi2m, ch.b[11]));
				w = Fr.sub(w, Fr.mul(ch.xim, ch.b[10]));
			}

			// Add blinding scalars b_10 and b_11 to the coefficient n
			if (i === zkey.domainSize) {
				w = Fr.add(w, ch.b[10]);
				w = Fr.add(w, Fr.mul(ch.xim, ch.b[11]));
			}

			pol_wxi.set(w, i * n8r);
		}

		let w0 = pol_wxi.slice(0, n8r);
		w0 = Fr.sub(w0, proof.eval_t);
		w0 = Fr.sub(w0, Fr.mul(ch.v[1], proof.eval_r));
		w0 = Fr.sub(w0, Fr.mul(ch.v[2], proof.eval_a));
		w0 = Fr.sub(w0, Fr.mul(ch.v[3], proof.eval_b));
		w0 = Fr.sub(w0, Fr.mul(ch.v[4], proof.eval_c));
		w0 = Fr.sub(w0, Fr.mul(ch.v[5], proof.eval_s1));
		w0 = Fr.sub(w0, Fr.mul(ch.v[6], proof.eval_s2));
		pol_wxi.set(w0, 0);

		pol_wxi = divPol1(pol_wxi, ch.xi);

		proof.Wxi = await expTau(pol_wxi, "multiexp Wxi");

		let pol_wxiw = new ffjavascript.BigBuffer((zkey.domainSize + 3) * n8r);
		for (let i = 0; i < zkey.domainSize + 3; i++) {
			const w = pol_z.slice(i * n8r, (i + 1) * n8r);
			pol_wxiw.set(w, i * n8r);
		}
		w0 = pol_wxiw.slice(0, n8r);
		w0 = Fr.sub(w0, proof.eval_zw);
		pol_wxiw.set(w0, 0);

		pol_wxiw = divPol1(pol_wxiw, Fr.mul(ch.xi, Fr.w[zkey.power]));
		proof.Wxiw = await expTau(pol_wxiw, "multiexp Wxiw");
	}

	// async function hashToFr(transcript) {
	// 	const v = Scalar.fromRprBE(
	// 		new Uint8Array(keccak256.arrayBuffer(transcript))
	// 	);
	// 	return Fr.e(v);
	// }

	function evalPol(P, x) {
		const n = P.byteLength / n8r;
		if (n == 0) return Fr.zero;
		let res = P.slice((n - 1) * n8r, n * n8r);
		for (let i = n - 2; i >= 0; i--) {
			res = Fr.add(Fr.mul(res, x), P.slice(i * n8r, (i + 1) * n8r));
		}
		return res;
	}

	function divPol1(P, d) {
		const n = P.byteLength / n8r;
		const res = new ffjavascript.BigBuffer(n * n8r);
		res.set(Fr.zero, (n - 1) * n8r);
		res.set(P.slice((n - 1) * n8r, n * n8r), (n - 2) * n8r);
		for (let i = n - 3; i >= 0; i--) {
			res.set(
				Fr.add(
					P.slice((i + 1) * n8r, (i + 2) * n8r),
					Fr.mul(d, res.slice((i + 1) * n8r, (i + 2) * n8r))
				),
				i * n8r
			);
		}
		if (!Fr.eq(P.slice(0, n8r), Fr.mul(Fr.neg(d), res.slice(0, n8r)))) {
			throw new Error("Polinomial does not divide");
		}
		return res;
	}

	async function expTau(b, name) {
		const n = b.byteLength / n8r;
		const PTauN = PTau.slice(0, n * curve.G1.F.n8 * 2);
		const bm = await curve.Fr.batchFromMontgomery(b);
		let res = await curve.G1.multiExpAffine(PTauN, bm, logger, name);
		res = curve.G1.toAffine(res);
		return res;
	}

	async function to4T(A, pz) {
		pz = pz || [];
		let a = await Fr.ifft(A);
		const a4 = new ffjavascript.BigBuffer(n8r * zkey.domainSize * 4);
		a4.set(a, 0);

		const a1 = new ffjavascript.BigBuffer(n8r * (zkey.domainSize + pz.length));
		a1.set(a, 0);
		for (let i = 0; i < pz.length; i++) {
			a1.set(
				Fr.add(
					a1.slice(
						(zkey.domainSize + i) * n8r,
						(zkey.domainSize + i + 1) * n8r
					),
					pz[i]
				),
				(zkey.domainSize + i) * n8r
			);
			a1.set(Fr.sub(a1.slice(i * n8r, (i + 1) * n8r), pz[i]), i * n8r);
		}
		const A4 = await Fr.fft(a4);
		return [a1, A4];
	}
}

async function plonk16ProveAgg(zkeyFileName, witnessDir, count, logger) {
	let outputs = [];
	for (let index = 0; index < count; index++) {
		outputs.push(
			await plonk16Prove(
				zkeyFileName,
				`${witnessDir}/witness${index + 1}.wtns`
			)
		);
	}
	return outputs;
}

/*
    Copyright 2021 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const { unstringifyBigInts: unstringifyBigInts$2 } = ffjavascript.utils;

async function plonkFullProve(
	_input,
	wasmFile,
	zkeyFileName,
	logger
) {
	const input = unstringifyBigInts$2(_input);

	const wtns = {
		type: "mem",
	};
	await wtnsCalculate(input, wasmFile, wtns);
	return await plonk16Prove(zkeyFileName, wtns, logger);
}

async function plonkFullProveAgg(
	_inputs,
	wasmFile,
	zkeyFileName,
	count,
	logger
) {
	let outputs = [];
	for (let index = 0; index < count; index++) {
		outputs.push(
			await plonkFullProve(_inputs[index], wasmFile, zkeyFileName, logger)
		);
	}
	return outputs;
}

/*
    Copyright 2021 0kims association.

    This file is part of snarkjs.

    snarkjs is a free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License as published by the
    Free Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    snarkjs is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    snarkjs. If not, see <https://www.gnu.org/licenses/>.
*/
const { unstringifyBigInts: unstringifyBigInts$1 } = ffjavascript.utils;

async function plonkVerify(
	_vk_verifier,
	_publicSignals,
	_proof,
	logger
) {
	let vk_verifier = unstringifyBigInts$1(_vk_verifier);
	let proof = unstringifyBigInts$1(_proof);
	let publicSignals = unstringifyBigInts$1(_publicSignals);

	const curve = await getCurveFromName(vk_verifier.curve);

	const Fr = curve.Fr;
	const G1 = curve.G1;

	proof = fromObjectProof(curve, proof);
	vk_verifier = fromObjectVk(curve, vk_verifier);
	if (!isWellConstructed(curve, proof)) {
		logger.error("Proof is not well constructed");
		return false;
	}
	if (publicSignals.length != vk_verifier.nPublic) {
		logger.error("Invalid number of public inputs");
		return false;
	}
	const challanges = await calculateChallanges(curve, proof, publicSignals);
	if (logger) {
		logger.debug("beta: " + Fr.toString(challanges.beta, 16));
		logger.debug("gamma: " + Fr.toString(challanges.gamma, 16));
		logger.debug("alpha: " + Fr.toString(challanges.alpha, 16));
		logger.debug("xi: " + Fr.toString(challanges.xi, 16));
		logger.debug("v1: " + Fr.toString(challanges.v[1], 16));
		logger.debug("v5: " + Fr.toString(challanges.v[5], 16));
		logger.debug("v6: " + Fr.toString(challanges.v[6], 16));
		logger.debug("u: " + Fr.toString(challanges.u, 16));
	}
	const L = calculateLagrangeEvaluations(curve, challanges, vk_verifier);
	if (logger) {
		logger.debug("Lagrange Evaluations: ");
		for (let i = 1; i < L.length; i++) {
			logger.debug(`L${i}(xi)=` + Fr.toString(L[i], 16));
		}
	}

	if (publicSignals.length != vk_verifier.nPublic) {
		logger.error("Number of public signals does not match with vk");
		return false;
	}

	const pl = calculatePl(curve, publicSignals, L);
	if (logger) {
		logger.debug("Pl: " + Fr.toString(pl, 16));
	}

	const t = calculateT(curve, proof, challanges, pl, L[1]);
	if (logger) {
		logger.debug("t: " + Fr.toString(t, 16));
	}

	const D = calculateD(curve, proof, challanges, vk_verifier, L[1]);
	if (logger) {
		logger.debug("D: " + G1.toString(G1.toAffine(D), 16));
	}

	const F = calculateF(curve, proof, challanges, vk_verifier, D);
	if (logger) {
		logger.debug("F: " + G1.toString(G1.toAffine(F), 16));
	}

	const E = calculateE(curve, proof, challanges, vk_verifier, t);
	if (logger) {
		logger.debug("E: " + G1.toString(G1.toAffine(E), 16));
	}

	const res = await isValidPairing(
		curve,
		proof,
		challanges,
		vk_verifier,
		E,
		F
	);

	if (logger) {
		if (res) {
			logger.info("OK!");
		} else {
			logger.warn("Invalid Proof");
		}
	}

	return res;
}

function fromObjectProof(curve, proof) {
	const G1 = curve.G1;
	const Fr = curve.Fr;
	const res = {};
	res.A = G1.fromObject(proof.A);
	res.B = G1.fromObject(proof.B);
	res.C = G1.fromObject(proof.C);
	res.Z = G1.fromObject(proof.Z);
	res.T1 = G1.fromObject(proof.T1);
	res.T2 = G1.fromObject(proof.T2);
	res.T3 = G1.fromObject(proof.T3);
	res.eval_a = Fr.fromObject(proof.eval_a);
	res.eval_b = Fr.fromObject(proof.eval_b);
	res.eval_c = Fr.fromObject(proof.eval_c);
	res.eval_zw = Fr.fromObject(proof.eval_zw);
	res.eval_s1 = Fr.fromObject(proof.eval_s1);
	res.eval_s2 = Fr.fromObject(proof.eval_s2);
	res.eval_r = Fr.fromObject(proof.eval_r);
	res.Wxi = G1.fromObject(proof.Wxi);
	res.Wxiw = G1.fromObject(proof.Wxiw);

	// console.log(`A: ${G1.toString(G1.toAffine(res.A), 16)}`);
	// console.log(`B: ${G1.toString(G1.toAffine(res.B), 16)}`);
	// console.log(`C: ${G1.toString(G1.toAffine(res.C), 16)}`);
	// console.log(`Z: ${G1.toString(G1.toAffine(res.Z), 16)}`);
	// console.log(`T1: ${G1.toString(G1.toAffine(res.T1), 16)}`);
	// console.log(`T2: ${G1.toString(G1.toAffine(res.T2), 16)}`);
	// console.log(`T3: ${G1.toString(G1.toAffine(res.T3), 16)}`);
	// console.log(`Wxi: ${G1.toString(G1.toAffine(res.Wxi), 16)}`);
	// console.log(`Wxiw: ${G1.toString(G1.toAffine(res.Wxiw), 16)}`);

	return res;
}

function fromObjectVk(curve, vk) {
	const G1 = curve.G1;
	const G2 = curve.G2;
	const Fr = curve.Fr;
	const res = vk;
	res.Qm = G1.fromObject(vk.Qm);
	res.Ql = G1.fromObject(vk.Ql);
	res.Qr = G1.fromObject(vk.Qr);
	res.Qo = G1.fromObject(vk.Qo);
	res.Qc = G1.fromObject(vk.Qc);
	res.S1 = G1.fromObject(vk.S1);
	res.S2 = G1.fromObject(vk.S2);
	res.S3 = G1.fromObject(vk.S3);
	res.k1 = Fr.fromObject(vk.k1);
	res.k2 = Fr.fromObject(vk.k2);
	res.X_2 = G2.fromObject(vk.X_2);

	return res;
}

function isWellConstructed(curve, proof) {
	const G1 = curve.G1;
	if (!G1.isValid(proof.A)) return false;
	if (!G1.isValid(proof.B)) return false;
	if (!G1.isValid(proof.C)) return false;
	if (!G1.isValid(proof.Z)) return false;
	if (!G1.isValid(proof.T1)) return false;
	if (!G1.isValid(proof.T2)) return false;
	if (!G1.isValid(proof.T3)) return false;
	if (!G1.isValid(proof.Wxi)) return false;
	if (!G1.isValid(proof.Wxiw)) return false;
	return true;
}

async function calculateChallanges(curve, proof, publicSignals) {
	curve.G1;
	const Fr = curve.Fr;
	curve.Fr.n8;
	const res = {};

	// instantiate Transcript
	let transcript = new Transcript(poseidon_spec, curve);
	transcript.load();

	// const transcript1 = new Uint8Array(
	// 	publicSignals.length * n8r + G1.F.n8 * 2 * 3
	// );
	for (let i = 0; i < publicSignals.length; i++) {
		transcript.writeScalar(Fr.e(publicSignals[i]), `pi ${i}`);
		// Fr.toRprBE(transcript1, i * n8r, Fr.e(publicSignals[i]));
	}

	transcript.writePoint(proof.A, "A");
	transcript.writePoint(proof.B, "B");
	transcript.writePoint(proof.C, "C");

	// G1.toRprUncompressed(transcript1, publicSignals.length * n8r + 0, proof.A);
	// G1.toRprUncompressed(
	// 	transcript1,
	// 	publicSignals.length * n8r + G1.F.n8 * 2,
	// 	proof.B
	// );
	// G1.toRprUncompressed(
	// 	transcript1,
	// 	publicSignals.length * n8r + G1.F.n8 * 4,
	// 	proof.C
	// );

	res.beta = transcript.squeezeChallenge();

	// const transcript2 = new Uint8Array(n8r);
	// Fr.toRprBE(transcript2, 0, res.beta);
	transcript.writeScalar(res.beta, "beta");
	res.gamma = transcript.squeezeChallenge();

	// const transcript3 = new Uint8Array(G1.F.n8 * 2);
	// G1.toRprUncompressed(transcript3, 0, proof.Z);
	transcript.writePoint(proof.Z, "Z");
	res.alpha = transcript.squeezeChallenge();

	// const transcript4 = new Uint8Array(G1.F.n8 * 2 * 3);
	// G1.toRprUncompressed(transcript4, 0, proof.T1);
	// G1.toRprUncompressed(transcript4, G1.F.n8 * 2, proof.T2);
	// G1.toRprUncompressed(transcript4, G1.F.n8 * 4, proof.T3);
	transcript.writePoint(proof.T1, "T1");
	transcript.writePoint(proof.T2, "T2");
	transcript.writePoint(proof.T3, "T3");
	res.xi = transcript.squeezeChallenge();

	// const transcript5 = new Uint8Array(n8r * 7);
	// Fr.toRprBE(transcript5, 0, proof.eval_a);
	// Fr.toRprBE(transcript5, n8r, proof.eval_b);
	// Fr.toRprBE(transcript5, n8r * 2, proof.eval_c);
	// Fr.toRprBE(transcript5, n8r * 3, proof.eval_s1);
	// Fr.toRprBE(transcript5, n8r * 4, proof.eval_s2);
	// Fr.toRprBE(transcript5, n8r * 5, proof.eval_zw);
	// Fr.toRprBE(transcript5, n8r * 6, proof.eval_r);
	transcript.writeScalar(proof.eval_a, "eval_a");
	transcript.writeScalar(proof.eval_b, "eval_b");
	transcript.writeScalar(proof.eval_c, "eval_c");
	transcript.writeScalar(proof.eval_s1, "eval_s1");
	transcript.writeScalar(proof.eval_s2, "eval_s2");
	transcript.writeScalar(proof.eval_zw, "eval_zw");
	transcript.writeScalar(proof.eval_r, "eval_r");
	res.v = [];
	res.v[1] = transcript.squeezeChallenge();

	for (let i = 2; i <= 6; i++) res.v[i] = Fr.mul(res.v[i - 1], res.v[1]);

	// const transcript6 = new Uint8Array(G1.F.n8 * 2 * 2);
	// G1.toRprUncompressed(transcript6, 0, proof.Wxi);
	// G1.toRprUncompressed(transcript6, G1.F.n8 * 2, proof.Wxiw);
	transcript.writePoint(proof.Wxi, "Wxi");
	transcript.writePoint(proof.Wxiw, "Wxiw");
	res.u = transcript.squeezeChallenge();

	return res;
}

function calculateLagrangeEvaluations(curve, challanges, vk) {
	const Fr = curve.Fr;

	let xin = challanges.xi;
	let domainSize = 1;
	for (let i = 0; i < vk.power; i++) {
		xin = Fr.square(xin);
		domainSize *= 2;
	}
	challanges.xin = xin;

	challanges.zh = Fr.sub(xin, Fr.one);
	const L = [];

	const n = Fr.e(domainSize);
	let w = Fr.one;
	for (let i = 1; i <= Math.max(1, vk.nPublic); i++) {
		L[i] = Fr.div(
			Fr.mul(w, challanges.zh),
			Fr.mul(n, Fr.sub(challanges.xi, w))
		);
		w = Fr.mul(w, Fr.w[vk.power]);
	}

	return L;
}

// async function hashToFr(curve, transcript) {
// 	const v = Scalar.fromRprBE(
// 		new Uint8Array(keccak256.arrayBuffer(transcript))
// 	);
// 	return curve.Fr.e(v);
// }

function calculatePl(curve, publicSignals, L) {
	const Fr = curve.Fr;

	let pl = Fr.zero;
	for (let i = 0; i < publicSignals.length; i++) {
		const w = Fr.e(publicSignals[i]);
		pl = Fr.sub(pl, Fr.mul(w, L[i + 1]));
	}
	return pl;
}

function calculateT(curve, proof, challanges, pl, l1) {
	const Fr = curve.Fr;
	let num = proof.eval_r;
	num = Fr.add(num, pl);

	let e1 = proof.eval_a;
	e1 = Fr.add(e1, Fr.mul(challanges.beta, proof.eval_s1));
	e1 = Fr.add(e1, challanges.gamma);

	let e2 = proof.eval_b;
	e2 = Fr.add(e2, Fr.mul(challanges.beta, proof.eval_s2));
	e2 = Fr.add(e2, challanges.gamma);

	let e3 = proof.eval_c;
	e3 = Fr.add(e3, challanges.gamma);

	let e = Fr.mul(Fr.mul(e1, e2), e3);
	e = Fr.mul(e, proof.eval_zw);
	e = Fr.mul(e, challanges.alpha);

	num = Fr.sub(num, e);

	num = Fr.sub(num, Fr.mul(l1, Fr.square(challanges.alpha)));

	const t = Fr.div(num, challanges.zh);

	return t;
}

function calculateD(curve, proof, challanges, vk, l1) {
	const G1 = curve.G1;
	const Fr = curve.Fr;

	let s1 = Fr.mul(Fr.mul(proof.eval_a, proof.eval_b), challanges.v[1]);
	let res = G1.timesFr(vk.Qm, s1);

	let s2 = Fr.mul(proof.eval_a, challanges.v[1]);
	res = G1.add(res, G1.timesFr(vk.Ql, s2));

	let s3 = Fr.mul(proof.eval_b, challanges.v[1]);
	res = G1.add(res, G1.timesFr(vk.Qr, s3));

	let s4 = Fr.mul(proof.eval_c, challanges.v[1]);
	res = G1.add(res, G1.timesFr(vk.Qo, s4));

	res = G1.add(res, G1.timesFr(vk.Qc, challanges.v[1]));

	const betaxi = Fr.mul(challanges.beta, challanges.xi);
	let s6a = proof.eval_a;
	s6a = Fr.add(s6a, betaxi);
	s6a = Fr.add(s6a, challanges.gamma);

	let s6b = proof.eval_b;
	s6b = Fr.add(s6b, Fr.mul(betaxi, vk.k1));
	s6b = Fr.add(s6b, challanges.gamma);

	let s6c = proof.eval_c;
	s6c = Fr.add(s6c, Fr.mul(betaxi, vk.k2));
	s6c = Fr.add(s6c, challanges.gamma);

	let s6 = Fr.mul(Fr.mul(s6a, s6b), s6c);
	s6 = Fr.mul(s6, Fr.mul(challanges.alpha, challanges.v[1]));

	let s6d = Fr.mul(Fr.mul(l1, Fr.square(challanges.alpha)), challanges.v[1]);
	s6 = Fr.add(s6, s6d);

	s6 = Fr.add(s6, challanges.u);
	res = G1.add(res, G1.timesFr(proof.Z, s6));

	let s7a = proof.eval_a;
	s7a = Fr.add(s7a, Fr.mul(challanges.beta, proof.eval_s1));
	s7a = Fr.add(s7a, challanges.gamma);

	let s7b = proof.eval_b;
	s7b = Fr.add(s7b, Fr.mul(challanges.beta, proof.eval_s2));
	s7b = Fr.add(s7b, challanges.gamma);

	let s7 = Fr.mul(s7a, s7b);
	s7 = Fr.mul(s7, challanges.alpha);
	s7 = Fr.mul(s7, challanges.v[1]);
	s7 = Fr.mul(s7, challanges.beta);
	s7 = Fr.mul(s7, proof.eval_zw);
	res = G1.sub(res, G1.timesFr(vk.S3, s7));

	return res;
}

function calculateF(curve, proof, challanges, vk, D) {
	const G1 = curve.G1;
	const Fr = curve.Fr;

	let res = proof.T1;

	res = G1.add(res, G1.timesFr(proof.T2, challanges.xin));
	res = G1.add(res, G1.timesFr(proof.T3, Fr.square(challanges.xin)));
	res = G1.add(res, D);
	res = G1.add(res, G1.timesFr(proof.A, challanges.v[2]));
	res = G1.add(res, G1.timesFr(proof.B, challanges.v[3]));
	res = G1.add(res, G1.timesFr(proof.C, challanges.v[4]));
	res = G1.add(res, G1.timesFr(vk.S1, challanges.v[5]));
	res = G1.add(res, G1.timesFr(vk.S2, challanges.v[6]));

	return res;
}

function calculateE(curve, proof, challanges, vk, t) {
	const G1 = curve.G1;
	const Fr = curve.Fr;

	let s = t;

	s = Fr.add(s, Fr.mul(challanges.v[1], proof.eval_r));
	s = Fr.add(s, Fr.mul(challanges.v[2], proof.eval_a));
	s = Fr.add(s, Fr.mul(challanges.v[3], proof.eval_b));
	s = Fr.add(s, Fr.mul(challanges.v[4], proof.eval_c));
	s = Fr.add(s, Fr.mul(challanges.v[5], proof.eval_s1));
	s = Fr.add(s, Fr.mul(challanges.v[6], proof.eval_s2));
	s = Fr.add(s, Fr.mul(challanges.u, proof.eval_zw));

	const res = G1.timesFr(G1.one, s);

	return res;
}

async function isValidPairing(curve, proof, challanges, vk, E, F) {
	const G1 = curve.G1;
	const Fr = curve.Fr;

	let A1 = proof.Wxi;
	A1 = G1.add(A1, G1.timesFr(proof.Wxiw, challanges.u));

	let B1 = G1.timesFr(proof.Wxi, challanges.xi);
	const s = Fr.mul(Fr.mul(challanges.u, challanges.xi), Fr.w[vk.power]);
	B1 = G1.add(B1, G1.timesFr(proof.Wxiw, s));
	B1 = G1.add(B1, F);
	B1 = G1.sub(B1, E);

	const res = await curve.pairingEq(G1.neg(A1), vk.X_2, B1, curve.G2.one);

	return res;
}

/*
    Copyright 2021 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/
const { unstringifyBigInts} = ffjavascript.utils;

function i2hex(i) {
    return ("0" + i.toString(16)).slice(-2);
}

function p256(n) {
    let nstr = n.toString(16);
    while (nstr.length < 64) nstr = "0"+nstr;
    nstr = `"0x${nstr}"`;
    return nstr;
}

async function plonkExportSolidityCallData(_proof, _pub) {
    const proof = unstringifyBigInts(_proof);
    const pub = unstringifyBigInts(_pub);

    const curve = await getCurveFromName(proof.curve);
    const G1 = curve.G1;
    const Fr = curve.Fr;

    let inputs = "";
    for (let i=0; i<pub.length; i++) {
        if (inputs != "") inputs = inputs + ",";
        inputs = inputs + p256(pub[i]);
    }

    const proofBuff = new Uint8Array(G1.F.n8*2*9 + Fr.n8*7);
    G1.toRprUncompressed(proofBuff, 0, G1.e(proof.A));
    G1.toRprUncompressed(proofBuff, G1.F.n8*2, G1.e(proof.B));
    G1.toRprUncompressed(proofBuff, G1.F.n8*4, G1.e(proof.C));
    G1.toRprUncompressed(proofBuff, G1.F.n8*6, G1.e(proof.Z));
    G1.toRprUncompressed(proofBuff, G1.F.n8*8, G1.e(proof.T1));
    G1.toRprUncompressed(proofBuff, G1.F.n8*10, G1.e(proof.T2));
    G1.toRprUncompressed(proofBuff, G1.F.n8*12, G1.e(proof.T3));
    G1.toRprUncompressed(proofBuff, G1.F.n8*14, G1.e(proof.Wxi));
    G1.toRprUncompressed(proofBuff, G1.F.n8*16, G1.e(proof.Wxiw));
    Fr.toRprBE(proofBuff, G1.F.n8*18 , Fr.e(proof.eval_a));
    Fr.toRprBE(proofBuff, G1.F.n8*18 + Fr.n8, Fr.e(proof.eval_b));
    Fr.toRprBE(proofBuff, G1.F.n8*18 + Fr.n8*2, Fr.e(proof.eval_c));
    Fr.toRprBE(proofBuff, G1.F.n8*18 + Fr.n8*3, Fr.e(proof.eval_s1));
    Fr.toRprBE(proofBuff, G1.F.n8*18 + Fr.n8*4, Fr.e(proof.eval_s2));
    Fr.toRprBE(proofBuff, G1.F.n8*18 + Fr.n8*5, Fr.e(proof.eval_zw));
    Fr.toRprBE(proofBuff, G1.F.n8*18 + Fr.n8*6, Fr.e(proof.eval_r));

    const proofHex = Array.from(proofBuff).map(i2hex).join("");

    const S="0x"+proofHex+",["+inputs+"]";

    return S;
}

/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

var plonk = /*#__PURE__*/Object.freeze({
    __proto__: null,
    setup: plonkSetup,
    fullProve: plonkFullProve,
    fullProveAgg: plonkFullProveAgg,
    prove: plonk16Prove,
    proveAgg: plonk16ProveAgg,
    verify: plonkVerify,
    exportSolidityCallData: plonkExportSolidityCallData
});

exports.groth16 = groth16;
exports.plonk = plonk;
exports.powersOfTau = powersoftau;
exports.r1cs = r1cs;
exports.wtns = wtns;
exports.zKey = zkey;
