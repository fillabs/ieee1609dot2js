import { Enumerated, Integer, Sequence, 
         SequenceOf, Choice, OctetString,
         IA5String, BitString, Uint8,
         Uint16, OpenType
       } from "asnjs";

import * as crypto from 'crypto';
import { isArray, inspect } from "util";

const _emptyStringHash = {
    sha256: new Uint8Array([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    ]),
    sha384: new Uint8Array([
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
        0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
        0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
    ])
};

const _der_prefix = {
    prime256v1: new Uint8Array([
        0x30, 0x39, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x22, 0x00]),
    brainpoolP256r1: new Uint8Array([
        0x30, 0x3A, 0x30, 0x14, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x09, 0x2B,
        0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07, 0x03, 0x22, 0x00]),
    brainpoolP384r1: new Uint8Array([
        0X30, 0X4A, 0X30, 0X14, 0X06, 0X07, 0X2A, 0X86, 0X48, 0XCE, 0X3D, 0X02, 0X01, 0X06, 0X09, 0X2B,
        0X24, 0X03, 0X03, 0X02, 0X08, 0X01, 0X01, 0X0B, 0X03, 0X32, 0X00])
};

class HashAlgorithm extends Enumerated([
    "sha256", 'EXTENSION', "sha384"
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
    get algorithm() {
        return this.fields[this];
    }
}

class OctetString16 extends OctetString(16)
{
    [inspect.custom]() {
        return "\n  " + Buffer.from(this).toString('hex');
    }

}

class OctetString32 extends OctetString(32)
{
    [inspect.custom]() {
        let b = Buffer.from(this);
        return "\n  " + b.toString('hex', 0,  16) +
               "\n  " + b.toString('hex', 16, 32);
    }
}

class OctetString48 extends OctetString(48)
{
    [inspect.custom]() {
        let b = Buffer.from(this);
        return "\n  " + b.toString('hex', 0,  16) +
               "\n  " + b.toString('hex', 16, 32) +
               "\n  " + b.toString('hex', 32, 48);
    }
}

class Opaque extends OctetString()
{
    static from_oer(dc) {
        return super.from_oer(dc);
    }
    [inspect.custom]() {
        return "\n  " + Buffer.from(this).toString('hex');
    }
}

class HashedId8 extends OctetString(8)
{
    [inspect.custom]() {
        return Buffer.from(this).toString('hex');
    }
}

class HashedId3 extends OctetString(3)
{
    [inspect.custom]() {
        return Buffer.from(this).toString('hex');
    }
}

const epoch = new Date("2004-01-01 00:00:00").getTime();
class Time64 extends Date {
    static from_oer(dc) {
        var t = dc.getUint64();
        var r = new this(epoch + Number(t / 1000n));
        r.time64 = t;
        return r;
    }
}

class Time32 extends Date {
    static from_oer(dc) {
        var t = dc.getUint32();
        return new this(t * 1000 + epoch);
    }
}

class IssuerIdentifier extends Choice([
    {
        name: "sha256AndDigest",
        type: HashedId8
    }, {
        name: "self",
        type: HashAlgorithm
    }, {
        extension: true
    }, {
        name: "sha384AndDigest",
        type: HashedId8
    }
]) {
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

class CertificateId extends Choice([
    {
        name: "linkageData",
        type: Sequence([
            {
                name: "iCert",
                type: Uint16
            }, {
                name: "linkage_value",
                type: OctetString(9)
            }, {
                name: "group_linkage_value",
                sequence: [
                    {
                        name: "jValue",
                        type: OctetString(4)
                    }, {
                        name: "value",
                        type: OctetString(9)
                    }
                ]
            }
        ])
    }, {
        name: "name",
        type: IA5String()
    }, {
        name: "binaryId",
        type: Opaque
    }, {
        name: "none"
    }, {
        extension: true
    }
]) { }

class ValidityPeriod extends Sequence([
    {
        name: "start",
        type: Time32
    }, {
        name: "duration",
        type: Choice([
            { name: "microseconds", type: Uint16 },
            { name: "milliseconds", type: Uint16 },
            { name: "seconds", type: Uint16 },
            { name: "minutes", type: Uint16 },
            { name: "hours", type: Uint16 },
            { name: "sixtyHours", type: Uint16 },
            { name: "years", type: Uint16 }
        ])
    }
]) { }

class Latitude extends Integer(-900000000, 900000001)
{
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

class Longitude extends Integer(-1799999999, 1800000001)
{
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

class TwoDLocation extends Sequence([
    {
        name: "latitude",
        type: Latitude
    }, {
        name: "longitude",
        type: Longitude
    }
])
{ }

class ThreeDLocation extends Sequence([
    {
        name: "latitude",
        type: Latitude
    }, {
        name: "longitude",
        type: Longitude
    }, {
        name: "elevation",
        type: Uint16
    }
])
{ }

class GeographicRegion extends Choice([
    {
        name: "circularRegion",
        type: Sequence([
            {
                name: "center",
                type: TwoDLocation
            }, {
                name: "radius",
                type: Uint16
            }
        ])
    }, {
        name: "rectangularRegion",
        type: SequenceOf(
            Sequence([
                {
                    name: "northWest",
                    type: TwoDLocation
                }, {
                    name: "southEast",
                    type: TwoDLocation
                }
            ])
        )
    }, {
        name: "polygonalRegion",
        type: SequenceOf(TwoDLocation)
    }, {
        name: "identifiedRegion",
        type: SequenceOf(
            Choice([
                {
                    name: "countryOnly",
                    type: Uint16
                }, {
                    name: "countryAndRegions",
                    sequence: [
                        {
                            name: "countryOnly",
                            type: Uint16
                        }, {
                            name: "regions",
                            type: SequenceOf(Uint8)
                        }
                    ]
                }, {
                    name: "countryAndSubregions",
                    type: Sequence([
                        {
                            name: "country",
                            type: Uint16
                        }, {
                            name: "regionAndSubregions",
                            type: SequenceOf(
                                Sequence([
                                    {
                                        name: "region",
                                        type: Uint8
                                    }, {
                                        name: "subregions",
                                        type: SequenceOf(Uint16)
                                    }
                                ])
                            )
                        }
                    ])
                }, {
                    extension: true
                }
            ])
        )
    }, {
        extension: true
    }

]) { }

class ServiceSpecificPermissions extends Choice([
    {
        name: "opaque",
        type: Opaque
    }, {
        extension:true
    }, {
        name: "bitmapSsp",
        type: Opaque
    }
]) { }

class Psid extends Integer(0)
{ }

class PsidSsp extends Sequence([
    {
        name: "psid",
        type: Psid
    }, {
        name: "ssp",
        optional: true,
        type: ServiceSpecificPermissions
    }
]) {
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

class EndEntityType extends BitString(8)
{ }

EndEntityType.app   = [true, false, false, false, false, false, false, false];
EndEntityType.enrol = [false, true, false, false, false, false, false, false];

class PsidGroupPermissions extends Sequence([
    {
        name: "subjectPermissions",
        type: Choice([
            {
                name: "explicit",
                type: SequenceOf(Sequence([
                    {
                        name: "psid",
                        type: Psid
                    }, {
                        name: "sspRange",
                        optional: true,
                        type: Choice([
                            {
                                name: "opaque",
                                type: SequenceOf(OctetString())
                            }, {
                                name: "all"
                            }, {
                                extension: true
                            }, {
                                name: "bitmapSspRange",
                                type: Sequence([
                                    {
                                        name: "sspValue",
                                        type: Opaque
                                    }, {
                                        name: "sspBitmask",
                                        type: Opaque
                                    }
                                ])
                            }
                        ])
                    }
                ]))
            }, {
                name: "all"
            }, {
                extension: true
            }
        ])
    }, {
        name: "minChainLength",
        type: Integer,
        default: 1
    }, {
        name: "chainLengthRange",
        type: Integer,
        default: 0
    }, {
        name: "eeType",
        type: EndEntityType,
        default: EndEntityType.app
    }
]) {
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

const _pointTypes = ["x_only", "reserved", "compressed_y_0", "compressed_y_1", "uncompressed"];

var EccCurvePoint = function (fields, options) {
    let C = class EccCurvePoint extends Choice(fields, options)
    {
        get x() {
            switch (this.tagIndex) {
                case 0:
                case 2:
                case 3:
                    return this[this.tagName];
                case 4:
                    return this.uncompressed.x;
            }
            return undefined;
        }
        get y() {
            if (this.tagIndex === 4) {
                return this.uncompressed.y;
            }
            return undefined;
        }

        to_der(algorithm) {
            var a;
            let prefix = _der_prefix[algorithm];
            if (this.tagIndex === 4) {
                a = new Uint8Array(prefix.length + 1 + 2 * this.uncompressed.x.length);
                a.set(prefix);
                a.set([this.tagIndex], prefix.length);
                a.set(this.uncompressed.x, prefix.length + 1);
                a.set(this.uncompressed.y, prefix.length + 1 + this.uncompressed.x.length);
            } else {
                a = new Uint8Array(prefix.length + 1 + this[this.tagName].length);
                a.set(prefix);
                a.set([this.tagIndex], prefix.length);
                a.set(this[this.tagName], prefix.length + 1);
            }
            return a;
        }
    };
    return C;
};

class EccP256CurvePoint extends EccCurvePoint([
    {
        name: _pointTypes[0],
        type: OctetString32
    }, {
        name: _pointTypes[1]
    }, {
        name: _pointTypes[2],
        type: OctetString32
    }, {
        name: _pointTypes[3],
        type: OctetString32
    }, {
        name: _pointTypes[4],
        type: Sequence([
            {
                name: "x",
                type: OctetString32
            }, {
                name: "y",
                type: OctetString32
            }
        ])
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

class EccP384CurvePoint extends EccCurvePoint([
    {
        name: _pointTypes[0],
        type: OctetString48
    }, {
        name: _pointTypes[1]
    }, {
        name: _pointTypes[2],
        type: OctetString48
    }, {
        name: _pointTypes[3],
        type: OctetString48
    }, {
        name: _pointTypes[4],
        type: Sequence([
            {
                name: "x",
                type: OctetString48
            }, {
                name: "y",
                type: OctetString48
            }
        ])
    }
]) {
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

class SymmetricEncryptionKey extends Enumerated([
    "aes128Ccm",
    Enumerated.extension
]) { }

class PublicEncryptionKey extends Sequence([
    {
        name: "supportedSymmAlg",
        type: SymmetricEncryptionKey
    }, {
        name: "publicKey",
        type: Choice([
            {
                name: "eciesNistP256",
                type: EccP256CurvePoint
            }, {
                name: "eciesBrainpoolP256r1",
                type: EccP256CurvePoint
            }, {
                extension: true
            }
        ])
    }
]) {
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

const _hashAlgorithms = ["sha256", "sha256", "sha384"];
const _verificationAlgorithms = ["prime256v1", "brainpoolP256r1", "brainpoolP384r1"];

class PublicVerificationKey extends Choice([
    {
        name: "ecdsaNistP256",
        type: EccP256CurvePoint
    }, {
        name: "ecdsaBrainpoolP256r1",
        type: EccP256CurvePoint
    }, {
        extension: true
    }, {
        name: "ecdsaBrainpoolP384r1",
        type: EccP384CurvePoint
    }
]) {
    hashAlgorithm() {
        return _hashAlgorithms[this.tagIndex];
    }
    verificationAlgorithm() {
        return _verificationAlgorithms[this.tagIndex];
    }
    to_der() {
        return this[this.tagName].to_der(this.verificationAlgorithm());
    }


//    static from_oer(dc) {
//        return super.from_oer(dc, { keep_buffer: true });
//    }
}

class SubjectAssurance extends Uint8 { }

class VerificationKeyIndicator extends Choice([
    {
        name: "verificationKey",
        type: PublicVerificationKey
    }, {
        name: "reconstructionValue",
        type: EccP256CurvePoint
    }, {
        extension:true
    }
]) {
    hashAlgorithm() {
        return this.verificationKey ? this.verificationKey.hashAlgorithm() : _hashAlgorithms[0];
    }
    verificationAlgorithm() {
        return this.verificationKey ? this.verificationKey.verificationAlgorithm() : _verificationAlgorithms[0];
    }
//    static from_oer(dc) {
//        return super.from_oer(dc, { keep_buffer: true });
//    }
}

class ToBeSignedCertificate extends Sequence([
    {
        name: "id",
        type: CertificateId
    }, {
        name: "cracaId",
        type: HashedId3
    }, {
        name: "crlSeries",
        type: Uint16
    }, {
        name: "validityPeriod",
        type: ValidityPeriod
    }, {
        name: "region",
        optional: true,
        type: GeographicRegion
    }, {
        name: "assuranceLevel",
        optional: true,
        type: SubjectAssurance
    }, {
        name: "appPermissions",
        optional: true,
        type: SequenceOf(PsidSsp)
    }, {
        name: "certIssuePermissions",
        optional: true,
        type: SequenceOf(PsidGroupPermissions)
    }, {
        name: "certRequestPermissions",
        optional: true,
        type: SequenceOf(PsidGroupPermissions)
    }, {
        name: "canRequestRollover",
        optional: true
    }, {
        name: "encryptionKey",
        optional: true,
        type: PublicEncryptionKey
    }, {
        name: "verifyKeyIndicator",
        type: VerificationKeyIndicator
    }, {
        extension: true
    }
]) {
    static from_oer(dc) {
        let x = super.from_oer(dc, { keep_buffer: true }); 
        return x;
    }
}


class EcdsaP256Signature extends Sequence([
    {
        name: "rSig",
        type: EccP256CurvePoint
    }, {
        name: "sSig",
        type: OctetString32
    }
]) {
    get ieee_p1363() {
        return new Uint8Array(Buffer.concat([this.rSig.x, this.sSig]));
    }
    static from_oer(dc) {
        let start = dc.index;
        let x = super.from_oer(dc);
        // canonicalize
        dc.dv.setUint8(start, 0x80);
        return x;
    }
}

class EcdsaP384Signature extends Sequence([
    {
        name: "rSig",
        type: EccP384CurvePoint
    }, {
        name: "sSig",
        type: OctetString48
    }
]) {
    get ieee_p1363() {
        let a = new Uint8Array(this.rSig.x.length + this.sSig.length);
        a.set(this.rSig.x);
        a.set(this.sSig, this.rSig.x.length);
        return a;
    }
    static from_oer(dc) {
        let start = dc.index;
        let x = super.from_oer(dc);
        // canonicalize
        dc.dv.setUint8(start, 0x80);
        return x;
    }
}


class Signature extends Choice([
    {
        name: "ecdsaNistP256Signature",
        type: EcdsaP256Signature
    }, {
        name: "ecdsaBrainpoolP256r1Signature",
        type: EcdsaP256Signature
    }, {
        extension: true
    }, {
        name: "ecdsaBrainpoolP384r1Signature",
        type: EcdsaP384Signature
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
    hashAlgorithm() {
        return _hashAlgorithms[this.tagIndex];
    }
    verificationAlgorithm() {
        return _verificationAlgorithms[this.tagIndex];
    }
    get ieee_p1363() {
        return this[this.tagName].ieee_p1363;
    }
}

class Ieee1609Dot2Certificate extends Sequence([
    {
        name: "version",
        type: Uint8
    }, {
        name: "type",
        type: Enumerated(["explicit", "implicit", Enumerated.extension])
    }, {
        name: "issuer",
        type: IssuerIdentifier
    }, {
        name: "toBeSigned",
        type: ToBeSignedCertificate
    }, {
        name: "signature",
        optional: true,
        type: Signature
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc, { keep_buffer: true });
    }

    get hash() {
        if (this._hash === undefined) {
            this._calculateHash();
        }
        return this._hash;
    }
    get digest() {
        let h = this.hash;
        return h.slice(h.length - 8);
    }

    get issuer_digest() {
        if (this.issuer.sha256AndDigest !== undefined) {
            return this.issuer.sha256AndDigest;
        } else if (this.issuer.sha384AndDigest !== undefined) {
            return this.issuer.sha384AndDigest;
        } else if (this.issuer.self !== undefined) {
            return this.digest;
        }
        return null;
    }
    get verificationKey() {
        if (this.toBeSigned.verifyKeyIndicator.verificationKey) {
            return crypto.createPublicKey({
                key: this.toBeSigned.verifyKeyIndicator.verificationKey.to_der(),
                format: "der",
                type: "spki"
            });
        }
    }
        

    get verificationHashAlgorithm() {
        return this.toBeSigned.verifyKeyIndicator.hashAlgorithm();
    }

    get verificationAlgorithm() {
        return this.toBeSigned.verifyKeyIndicator.verificationAlgorithm();
    }

    _calculateHash() {
        var hash;
        var data = this.oer;
        hash = crypto.createHash(this.verificationHashAlgorithm);
        hash.update(data);
        return this._hash = hash.digest();
    }

    verify(signer) {
        // check that signer is correct
        let issuer_digest = this.issuer_digest;
        if (typeof signer === "function") {
            signer = signer(issuer_digest);
        }
        if (!signer) {
            if (this.issuer.self) {
                signer = this;
            } else {
                return false;
            }
        }
        if (0 !== signer.digest.compare(issuer_digest)) {
            return false;
        }

        // calculate tbsHash
        let hashAlg = signer.verificationHashAlgorithm;
        let hash = crypto.createHash(hashAlg);
        hash.update(this.toBeSigned.oer);
        let d = hash.digest();
        console.log("TBS [" + this.toBeSigned.oer.length + "]: " + Buffer.from(this.toBeSigned.oer).toString('hex'));
        console.log("TBS hash: " + d.toString('hex'));
        let dd = new Uint8Array(d.length * 2);
        dd.set(d);
        if (this.issuer.self) {
            dd.set(_emptyStringHash[hashAlg], d.length);
        } else {
            let hash = crypto.createHash(hashAlg);
            hash.update(signer.oer);
            dd.set(hash.digest(), d.length);
        }

        let V = crypto.createVerify(hashAlg);
        V.update(dd);

        let k = {
            dsaEncoding: 'ieee-p1363',
            key: signer.toBeSigned.verifyKeyIndicator.verificationKey.to_der(),
            format: "der",
            type: "spki"
        };

        let s = this.signature.ieee_p1363;

        return V.verify(k, s);
    }
}

class SignerIdentifier extends Choice([
    {
        name: "digest",
        type: HashedId8
    }, {
        name: "certificate",
        type: SequenceOf(Ieee1609Dot2Certificate)
    }, {
        name: "self"
    }, {
        extension: true
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

class EciesP256EncryptedKey extends Sequence([
    {
        name: "v",
        type: EccP256CurvePoint
    }, {
        name: "c",
        type: OctetString16
    }, {
        name: "t",
        type: OctetString16
    }
]) { }

class PKRecipientInfo extends Sequence([
    {
        name: "recipientId",
        type: HashedId8
    }, {
        name: "encKey",
        type: Choice([
            {
                name: "eciesNistP256",
                type: EciesP256EncryptedKey
            }, {
                name: "eciesBrainpoolP256r1",
                type: EciesP256EncryptedKey
            }, {
                extension: true
            }
        ])
    }
]) { }

class AesCcmCiphertext extends Sequence([
    {
        name: "nonce",
        type: OctetString(12)
    }, {
        name: "ccmCiphertext",
        type: Opaque
    }
])
{
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}
class SymmetricCiphertext extends Choice([
    {
        name: "aes128ccm",
        type: AesCcmCiphertext
    }, {
        extension: true
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

var SignedDataPayload_Fields = [
    {
        name: "data",
        optional: true,
        type: null
    }, {
        name: "extDataHash",
        optional: true,
        type: Choice([
            {
                name: "sha256HashedData",
                type: OctetString32
            }, {
                extension: true
            }
        ])
    }, {
        extension: true
    }
];

class SignedDataPayload extends Sequence(SignedDataPayload_Fields)
{
    static from_oer(dc) {
        return super.from_oer(dc);
    }

}

class EtsiTs102941CrlRequest extends Sequence([
    {
        name: "issuerId",
        type: HashedId8,
    }, {
        name: "lastKnownUpdate",
        type: Time32,
        optional: true
    }
])
{ }

class EtsiTs102941CtlRequest extends Sequence([
    {
        name: "issuerId",
        type: HashedId8,
    }, {
        name: "lastKnownCtlSequence",
        type: Uint8,
        optional: true
    }
])
{ }

class EtsiOriginatingHeaderInfoExtension extends Sequence([
    {
        name: "id",
        key: "extensionId",
        type: Uint8
    }, {
        name: "content",
        type: OpenType({
            1: EtsiTs102941CrlRequest,
            2: EtsiTs102941CtlRequest
        }, "extensionId")
    }
])
{ }

class HeaderInfo extends Sequence([
    {
        name: "psid",
        type: Psid
    }, {
        name: "generationTime",
        optional: true,
        type: Time64
    }, {
        name: "expiryTime",
        optional: true,
        type: Time64
    }, {
        name: "generationLocation",
        optional: true,
        type: ThreeDLocation
    }, {
        name: "p2pcdLearningRequest",
        optional: true,
        type: HashedId3
    }, {
        name: "missingCrlIdentifier",
        optional: true,
        type: Sequence([
            {
                name: "cracaId",
                type: HashedId3
            }, {
                name: "crlSeries",
                type: Uint16
            }, {
                extension: true
            }
        ])
    }, {
        name: "encryptionKey",
        optional: true,
        type: Choice([
            {
                name: "public",
                type: PublicEncryptionKey
            }, {
                name: "symmetric",
                type: SymmetricEncryptionKey
            }
        ])
    }, {
        extension: true
    }, {
        name: "inlineP2pcdRequest",
        optional: true,
        type: SequenceOf(HashedId3)
    }, {
        name: "requestedCertificate",
        optional: true,
        type: Ieee1609Dot2Certificate
    }, {
        name: "pduFunctionalType",
        optional: true,
        type: Uint8
    }, {
        name: "contributedExtensions",
        optional: true,
        type: SequenceOf(
            Sequence([
                {
                    name: "contributorId",
                    type: Uint8,
                    key: "contributorId"
                }, {
                    name: "extns",
                    type: SequenceOf(
                        OpenType({
                            2: EtsiOriginatingHeaderInfoExtension
                        }, "contributorId")
                    )
                }
            ])
        )
    }
])
{
    static from_oer(dc, options) {
        return super.from_oer(dc, options);
    }
}


class ToBeSignedData extends Sequence([
    {
        name: "payload",
        type: SignedDataPayload
    }, {
        name: "headerInfo",
        type: HeaderInfo
    }
])
{
    static from_oer(dc) {
        return super.from_oer(dc, { keep_buffer: true });
    }
}
    
class SignedData extends Sequence([
    {
        name: "hashId",
        type: HashAlgorithm
    }, {
        name: "tbsData",
        type: ToBeSignedData
    }, {
        name: "signer",
        type: SignerIdentifier
    }, {
        name: "signature",
        type: Signature
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }

    get tbsHash() {

        var H = crypto.createHash(this.hashId.algorithm);
        if (H) {
            H.update(this.tbsData.oer);
            return H.digest();
        }
        return null;
    }

    verify(signer) {
        if (signer === undefined) {
            if (isArray(this.signer.certificate) && this.signer.certificate.length > 0)
                signer = this.signer.certificate[0];
            if (signer === undefined)
                return false;
        }
        let tbsHash = this.tbsHash;
        if (tbsHash) {
            console.log("TBS Hash: " + inspect(tbsHash, {
                depth: null, customInspect: true, maxArrayLength: null, showHidden: false
            }));
            console.log("Signer Hash: " + inspect(signer.hash, {
                depth: null, customInspect: true, maxArrayLength: null, showHidden: false
            }));
            let d = new Uint8Array(tbsHash.length + signer.hash.length);
            d.set(tbsHash);
            d.set(signer.hash, tbsHash.length);
/*
            let H = crypto.createHash(this.hashId.algorithm).update(d);
            d = H.digest()
            console.log("Signing Hash: " + inspect(d, {
                depth: null, customInspect: true, maxArrayLength: null, showHidden: false
            }));
*/

            let k = {
                dsaEncoding: 'ieee-p1363',
                key: signer.toBeSigned.verifyKeyIndicator.verificationKey.to_der(),
                format: "der",
                type: "spki"
            };

            let s = this.signature.ieee_p1363;

            let ret = crypto.verify(this.hashId.algorithm, d, k, s)

            return ret;
        }
    }
}

class RecipientInfo extends Choice([
    {
        name: "pskRecipInfo",
        type: HashedId8
    }, {
        name: "symmRecipInfo",
        type: Sequence([
            {
                name: "recipientId",
                type: HashedId8
            }, {
                name: "encKey",
                type: SymmetricCiphertext
            }
        ])
    }, {
        name: "certRecipInfo",
        type: PKRecipientInfo
    }, {
        name: "signedDataRecipInfo",
        type: PKRecipientInfo
    }, {
        name: "rekRecipInfo",
        type: PKRecipientInfo
    }
])
{
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

class EncryptedData extends Sequence([
    {
        name: "recipients",
        type: SequenceOf(RecipientInfo)
    }, {
        name: "ciphertext",
        type: SymmetricCiphertext
    }
])
{
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

class Ieee1609Dot2Content extends Choice([
    {
        name: "unsecuredData",
        type: Opaque
    }, {
        name: "signedData",
        type: SignedData
    }, {
        name: "encryptedData",
        type: EncryptedData
    }, {
        name: "signedCertificateRequest",
        type: OctetString()
    }, {
        extention: true
    }
])
{
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

class Ieee1609Dot2Data extends Sequence([
    {
        name: "protocolVersion",
        type: Uint8
    }, {
        name: "content",
        type: Ieee1609Dot2Content
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
    verify(signer) {
        if (this.content && this.content.signedData) {
            return this.content.signedData.verify(signer);
        }
        return false;
    }
}

SignedDataPayload_Fields[0].type = Ieee1609Dot2Data;

export {
    HashAlgorithm, Opaque, Time32, Time64, HashedId8, HashedId3, CertificateId, SubjectAssurance,
    GeographicRegion, ValidityPeriod, PsidGroupPermissions, PsidSsp,
    PublicEncryptionKey, PublicVerificationKey, Signature,
    Ieee1609Dot2Certificate, Ieee1609Dot2Data
};
