import { Enumerated, Integer, Sequence, 
         SequenceOf, Choice, OctetString,
         IA5String, BitString, Uint8,
         Uint16, OpenType, Null, ObjectIdentifier,
         DataCursor
       } from "asnjs";

var wc;
if (typeof process === 'object'){
    wc = (await import('crypto')).webcrypto; 
}else{
    wc = crypto;
}

var inspect_custom = Symbol.for('nodejs.util.inspect_custom')

var _emptyStringHash = {
    sha256: new Uint8Array([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    ]),
    sha384: new Uint8Array([
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
        0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
        0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
    ]),
    sm3: new Uint8Array([
        0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F, 0x8E, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
        0x22, 0xBE, 0xC8, 0xC7, 0x28, 0xFE, 0xFB, 0x74, 0x7E, 0xD0, 0x35, 0xEB, 0x50, 0x82, 0xAA, 0x2B
    ])
};
_emptyStringHash["SHA-256"] = _emptyStringHash.sha256;
_emptyStringHash["SHA-384"] = _emptyStringHash.sha384;
_emptyStringHash["SM3"]     = _emptyStringHash.sm3;

var _der_prefix = {
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
_der_prefix["P-256"] = _der_prefix.prime256v1;

/** @class 
 * @property {'SHA-256'|'SHA-384'|'SM3'} algorithm
 */
class HashAlgorithm extends Enumerated([
    "SHA-256", Enumerated.extension, "SHA-384", "SM3"
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
    get algorithm() {
        return this.fields[this];
    }
}

class CrlSeries extends Uint16{}

class OctetString16 extends OctetString(16) {}
class OctetString32 extends OctetString(32) {}
class OctetString48 extends OctetString(48) {}

class Opaque extends OctetString()
{
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

class HashedId8 extends OctetString(8) {}

class HashedId3 extends OctetString(3) {}

class IValue extends Uint16 {}

/** 
 * @class LaId
 *
 * @brief This structure contains a LA Identifier for use in the algorithms
 * specified in 5.1.3.4.
 */
 class LaId extends OctetString(2) {}
  
 /** 
  * @class LinkageSeed
  *
  * @brief This structure contains a linkage seed value for use in the
  * algorithms specified in 5.1.3.4.
  */
class LinkageSeed extends OctetString(16) {}

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
/**
 * @property {HashedId8} sha256AndDigest
 * @property {HashAlgorithm} self
 * @property {HashedId8} sha256AndDigest
 */
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

/**
 * @property {{iCert:Uint16, linkage_value: OctetString, group_linkage_value:{jValue:OctetString,value:OctetString}}} linkageData
 * @property {IA5String} name
 * @property {Opaque}    binaryId
 * @property {boolean}   none
 */
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
                type: Sequence([
                    {
                        name: "jValue",
                        type: OctetString(4)
                    }, {
                        name: "value",
                        type: OctetString(9)
                    }
                ])
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

/**
 *  @property {Uint16} milliseconds
 *  @property {Uint16} seconds
 *  @property {Uint16} minutes 
 *  @property {Uint16} microseconds
 *  @property {Uint16} hours
 *  @property {Uint16} sixtyHours
 *  @property {Uint16} years
*/ 
class Duration extends Choice([
    { name: "microseconds", type: Uint16 },
    { name: "milliseconds", type: Uint16 },
    { name: "seconds",      type: Uint16 },
    { name: "minutes",      type: Uint16 },
    { name: "hours",        type: Uint16 },
    { name: "sixtyHours",   type: Uint16 },
    { name: "years",        type: Uint16 }
]){}

/**
 * @property {Time32} start
 * @property {Duration} duration
 */
class ValidityPeriod extends Sequence([
    { name: "start",    type: Time32},
    { name: "duration", type: Duration}
]) { }

/**
 * @implements {Number}
 */
 class Latitude extends Integer(-900000000, 900000001)
{
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

/**
 * @implements {Number}
 */
class Longitude extends Integer(-1799999999, 1800000001)
{
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

/**
 * @property {Latitude} latitude
 * @property {Longitude} longitude
 */
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

/**
 * @property {Latitude} latitude
 * @property {Longitude} longitude
 * @property {Uint16} elevation
 */
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

/**
 * @property {{center:TwoDLocation, radius:Uint16}} circularRegion
 * @property {{northWest:TwoDLocation, southEast:TwoDLocation}[]} rectangularRegion
 * @property {TwoDLocation[]} polygonalRegion
 * @property {{countryOnly:Uint16,
 *             countryAndRegions:{countryOnly:Uint16, regions:Uint8[]},
 *             countryAndSubregions:{countryOnly:Uint16, regionAndSubregions:{region:Uint8, subregions:Uint16[]}[]}}} identifiedRegion
 */
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
                    type: Sequence([
                        {
                            name: "countryOnly",
                            type: Uint16
                        }, {
                            name: "regions",
                            type: SequenceOf(Uint8)
                        }
                    ])
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

/**
 * @property {Opaque} opaque
 * @property {Opaque} bitmapSsp
 */
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

/**
 * @implements {Number}
 */
class Psid extends Integer(0)
{ }
/**
 * @property {number} psid
 * @property {ServiceSpecificPermissions} ssp
 */
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

/**
 * @implements {boolean[]} 
 */
class EndEntityType extends BitString(8)
{ }

EndEntityType.app   = [true, false, false, false, false, false, false, false];
EndEntityType.enrol = [false, true, false, false, false, false, false, false];

/**
 * @property {{explicit:{
 *                psid:Psid,
 *                sspRange:{
 *                    opaque:string[],
 *                    all:boolean,
 *                    bitmapSspRange:{
 *                        sspValue:Opaque,
 *                        sspBitmask:Opaque}}}[],
 *             all:boolean}} subjectPermissions
 * @property {number} minChainLength
 * @property {number} chainLengthRange
 * @property {EndEntityType.app|EndEntityType.enrol} EndEntityType
 */
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
        type: Integer(),
        default: 1
    }, {
        name: "chainLengthRange",
        type: Integer(),
        default: 0
    }, {
        name: "eeType",
        type: EndEntityType,
        default: EndEntityType.app
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
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

/**
 * @class
 * @property {OctetString} x
 * @property {OctetString} y
 * @property {OctetString} x_only
 * @property {OctetString} compressed_y_0
 * @property {OctetString} compressed_y_1
 * @property {{x:OctetString,y:OctetString}} uncompressed
 */
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
/**
 * @function to_der
 * @memberof EccP256CurvePoint
 * @returns {Uint8Array}
 */

/**
 * @class
 * @property {OctetString} x
 * @property {OctetString} y
 * @property {OctetString} x_only
 * @property {OctetString} compressed_y_0
 * @property {OctetString} compressed_y_1
 * @property {{x:OctetString,y:OctetString}} uncompressed
 */
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
    Enumerated.extension,
    "sm4Ccm"
]) { }

/**
 * @property {'aes128Ccm'} supportedSymmAlg
 * @property {{eciesNistP256:EccP256CurvePoint, eciesBrainpoolP256r1: EccP256CurvePoint}} publicKey
 */
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
            }, {
                name: "ecencSm2",
                type: EccP256CurvePoint
            }
        ])
    }
]) {
//    static from_oer(dc) {
//        return super.from_oer(dc);
//    }
}

/** @typedef {('SHA-256'|'SHA-384'|'SM2')} HashAlgorithmValue */
const _hashAlgorithms = ["SHA-256", "SHA-256", "SHA-384", "SHA-384", "SM2"];
//const _verificationAlgorithms = ["prime256v1", "brainpoolP256r1", "brainpoolP384r1"];
/** @typedef {('P-256'|'B-256'|'P-384'|'B-384'|'SM3')} VerificationAlgorithmValue */
const _verificationAlgorithms = ["P-256", "B-256", "B-384", "P-384", "SM3"];

/**
 * @class
 * @property {EccP256CurvePoint} ecdsaNistP256
 * @property {EccP256CurvePoint} ecdsaBrainpoolP256r1
 * @property {EccP384CurvePoint} ecdsaBrainpoolP384r1
 */
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
    }, {
        name: "ecdsaNistP384",
        type: EccP384CurvePoint
    }, {
        name: "ecsigSm2",
        type: EccP256CurvePoint
    }
]) {
    /** @returns {HashAlgorithmValue} */
    hashAlgorithm() {
        return _hashAlgorithms[this.tagIndex];
    }
    /** @returns {VerificationAlgorithmValue} */
    verificationAlgorithm() {
        return _verificationAlgorithms[this.tagIndex];
    }
    /** @returns {Uint8Array} */
    to_der() {
        return this[this.tagName].to_der(this.verificationAlgorithm());
    }
}

class SubjectAssurance extends Uint8 { }

/**
 * @class
 * @property {PublicVerificationKey} verificationKey
 * @property {EccP256CurvePoint} reconstructionValue
 */
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
    /** @returns {HashAlgorithmValue} */
    hashAlgorithm() {
        return this.verificationKey ? this.verificationKey.hashAlgorithm() : _hashAlgorithms[0];
    }
    /** @returns {VerificationAlgorithmValue} */
    verificationAlgorithm() {
        return this.verificationKey ? this.verificationKey.verificationAlgorithm() : _verificationAlgorithms[0];
    }
}

class AppExtension extends Sequence([
    {
        name: "id",
        type: Uint8
    }, {
        name: "content",
        type: OpenType({
          1: ObjectIdentifier
        }, "id")
    }
]) {}

class CertIssueExtension extends Sequence([
    { name: "id",          type: Uint8 },
    { name: "permissions", type: Choice([
        { name: "specific", type: OpenType({1: Null}, "id")},
        { name: "all", type: Null }
      ])
    }
]) {}

class CertRequestExtension extends Sequence([
    { name: "id",          type: Uint8 },
    { name: "permissions", type: Choice([
        { name: "content", type: OpenType({1: Null}, "id")},
        { name: "all", type: Null }
      ])
    }
]) {}

/**
 * @property {CertificateId} id
 * @property {cracaId} OctetString
 * @property {crlSeries} number
 * @property {ValidityPeriod} validityPeriod
 * @property {?GeographicRegion} region
 * @property {?SubjectAssurance} assuranceLevel
 * @property {?PsidSsp[]} appPermissions
 * @property {?PsidGroupPermissions[]} certIssuePermissions
 * @property {?PsidGroupPermissions[]} certRequestPermissions
 * @property {?boolean} canRequestRollover
 * @property {?PublicEncryptionKey}encryptionKey
 * @property {VerificationKeyIndicator} verifyKeyIndicator
 * @property {?iBitString} flags
 * @property {?AppExtension[]} appExtensions
 * @property {?CertIssueExtension[]} certIssueExtensions
 * @property {?CertRequestExtension[]} certRequestExtension 
 */
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
    }, {
        name: "flags",
        type: BitString(8)
    }, {
        name: "appExtensions",
        type: SequenceOf(AppExtension)
    }, {
        name: "certIssueExtensions",
        type: SequenceOf(CertIssueExtension)
    }, {
        name: "certRequestExtension",
        type: SequenceOf(CertRequestExtension)
    }
]) {
    static from_oer(dc) {
        let x = super.from_oer(dc, { keep_buffer: true }); 
        return x;
    }
}

/**
 * @property {EccP256CurvePoint} rSig
 * @property {OctetString} sSig
 */
class EcdsaP256Signature extends Sequence([
    {
        name: "rSig",
        type: EccP256CurvePoint
    }, {
        name: "sSig",
        type: OctetString32
    }
]) {
    /** @returns {Uint8Array} returns the IEEE1363 signature representation: Concatenation of r and s */
    get ieee_p1363() {
        return Uint8Array.from([...this.rSig.x, ...this.sSig]);
    }
    static from_oer(dc) {
        let start = dc.index;
        let x = super.from_oer(dc);
        // canonicalize
        dc.dv.setUint8(start, 0x80);
        return x;
    }
}

/**
 * @property {EccP384CurvePoint} rSig
 * @property {OctetString} sSig
 */
 class EcdsaP384Signature extends Sequence([
    {
        name: "rSig",
        type: EccP384CurvePoint
    }, {
        name: "sSig",
        type: OctetString48
    }
]) {
    /** @returns {Uint8Array} returns the IEEE1363 signature representation: Concatenation of r and s */
    get ieee_p1363() {
        return Uint8Array.from([...this.rSig.x, ...this.sSig]);
    }

    static from_oer(dc) {
        let start = dc.index;
        let x = super.from_oer(dc);
        // canonicalize
        dc.dv.setUint8(start, 0x80);
        return x;
    }
}

/**
 * @property {EcdsaP256Signature} ecdsaNistP256Signature
 * @property {EcdsaP256Signature} ecdsaBrainpoolP256r1Signature
 * @property {EcdsaP384Signature} ecdsaBrainpoolP384r1Signature
 * @property {EcdsaP384Signature} ecdsaNistP384Signature
 * @property {EcdsaP256Signature} sm2Signature
 */
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
    }, {
        name: "ecdsaNistP384Signature",
        type: EcdsaP384Signature
    }, {
        name: "sm2Signature",
        type: EcdsaP256Signature
    }
]) {
    static from_oer(dc) {
        return super.from_oer(dc);
    }
    /**@returns {HashAlgorithmValue} */
    hashAlgorithm() {
        return _hashAlgorithms[this.tagIndex];
    }
    /**@returns {VerificationAlgorithmValue} */
    verificationAlgorithm() {
        return _verificationAlgorithms[this.tagIndex];
    }
    /**@returns {Uint8Array} */
    get ieee_p1363() {
        return this[this.tagName].ieee_p1363;
    }
}

class CertificateType extends Enumerated([
    "explicit",
    "implicit",
    Enumerated.extension
]){}

/**
 * @property {number} version
 * @property {('explicit'|'implicit')} type
 * @property {IssuerIdentifier} issuer
 * @property {ToBeSignedCertificate} toBeSigned
 * @property {Signature}signature
 */
class Ieee1609Dot2Certificate extends Sequence([
    {
        name: "version",
        type: Uint8
    }, {
        name: "type",
        type: CertificateType
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
    /**
     * 
     * @param {DataCursor} dc 
     * @returns {Ieee1609Dot2Certificate}
     */
    static from_oer(dc) {
        return super.from_oer(dc, { keep_buffer: true });
    }

    async _calculateHash() {
        return wc.subtle.digest(this.verificationHashAlgorithm, this.oer);
    }

    /**
     * @async
     * @returns {Uint8Array}
     */
     async hash() {
        if (this._hash === undefined) {
            this._hash = new Uint8Array( await this._calculateHash());
        }
        return this._hash;
    }

    /**
     * @async
     * @returns {HashedId8}
     */
     async digest() {
        let h = await this.hash();
        let l = h.length;
        return new HashedId8(h.slice(l-8));
    }

    /**
     * @async
     * @returns {HashedId8}
     */
     async issuer_digest() {
        if (this.issuer.sha256AndDigest !== undefined) {
            return this.issuer.sha256AndDigest;
        } else if (this.issuer.sha384AndDigest !== undefined) {
            return this.issuer.sha384AndDigest;
        } else if (this.issuer.self !== undefined) {
            return this.digest();
        }
        return null;
    }
    
    /**
     * @async
     * @returns {Promise<CryptoKey>} 
     */
     async verificationKey() {
        if (this.toBeSigned.verifyKeyIndicator.verificationKey) {
            let der = this.toBeSigned.verifyKeyIndicator.verificationKey.to_der();
            let va = this.toBeSigned.verifyKeyIndicator.verificationAlgorithm();
            return wc.subtle.importKey('spki', der ,
                                             { name: 'ECDSA', namedCurve: va},
                                             true, ['verify']);
        }
    }        

    /** @returns {HashAlgorithmValue} */
    get verificationHashAlgorithm() {
        return this.toBeSigned.verifyKeyIndicator.hashAlgorithm();
    }

    /** @returns {VerificationAlgorithmValue} */
    get verificationAlgorithm() {
        return this.toBeSigned.verifyKeyIndicator.verificationAlgorithm();
    }

    /** 
     * @async
     * @returns {Promise<boolean>} */
    async verify(signer) {
        // check that signer is correct
        let issuer_digest = await this.issuer_digest();
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
        if(!issuer_digest.equal(await signer.digest()))
            return false;

        // calculate tbsHash
        let hashAlg = signer.verificationHashAlgorithm;
        let tbsHash = await wc.subtle.digest(hashAlg, this.toBeSigned.oer);
    
//        console.log("TBS [" + this.toBeSigned.oer.length + "]: " + this.toBeSigned.oer.toString('hex'));
//        console.log("TBS hash: " + tbsHash.toString('hex'));
        let signerDigest = (this.issuer.self) ? _emptyStringHash[hashAlg] : await signer.hash();
        let verificationKey = await signer.verificationKey();
        let dd = Uint8Array.from([...new Uint8Array(tbsHash), ...signerDigest]);
        let passed;
        try {
            let s = this.signature.ieee_p1363;
            passed = wc.subtle.verify( { name:'ECDSA', hash: hashAlg },verificationKey, s, dd);
        }catch(e){
            console.log(e);
            passed = false;
        }
        return passed;
    }
}
/**
 * @property {HashedId8} digest
 * @property {Ieee1609Dot2Certificate[]} certificate
 * @property {boolean}self
 */
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
    /**
     * @param {DataCursor} dc 
     * @returns {SignerIdentifier}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}
/** 
 * @property {EccP256CurvePoint} v
 * @property {OctetString} c
 * @property {OctetString} t
 */

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

/**
 * @property {HashedId8} recipientId
 * @property {{eciesNistP256:EciesP256EncryptedKey,eciesBrainpoolP256r1:EciesP256EncryptedKey}}encKey
 */
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

/**
 * @property {OctetString}nonce
 * @property {Opaque} ccmCiphertext
 */ 
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
    /**
     * 
     * @param {DataCursor} dc 
     * @returns {AesCcmCiphertext}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}
/**
 * @property {AesCcmCiphertext} aes128ccm
 */
class SymmetricCiphertext extends Choice([
    {
        name: "aes128ccm",
        type: AesCcmCiphertext
    }, {
        extension: true
    }
]) {
    /**
     * 
     * @param {DataCursor} dc 
     * @returns {SymmetricCiphertext}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

var SignedDataPayload_Fields = [
    {
        name: "data",
        optional: true,
        type: null // to be changed to Ieee1609Dot2Data at the end of the file
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
/**
 * @property {Ieee1609Dot2Data} data
 * @property {{sha256HashedData:OctetString}} extDataHash
 */
class SignedDataPayload extends Sequence(SignedDataPayload_Fields)
{
    /**
     * @static
     * @param {DataCursor} dc
     * @returns {SignedDataPayload}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

/**
 * @property {HashedId8} issuerId
 * @property {Time32} lastKnownUpdate
 */

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
/**
 * @property {HashedId8} issuerId
 * @property {Uint8} lastKnownCtlSequence
 */
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

/**
 * @property {Uint8} id
 * @property {(EtsiTs102941CrlRequest|EtsiTs102941CtlRequest)} content
 */
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

/**
 * @property {Psid} psid
 * @property {?Time64} generationTime
 * @property {?Time64} expiryTime
 * @property {?ThreeDLocation} generationLocation
 * @property {?HashedId3} p2pcdLearningRequest
 * @property {?{cracaId:HashedId3,crlSeries:Uint16}[]} missingCrlIdentifier
 * @property {?{public:PublicEncryptionKey, symmetric:SymmetricEncryptionKey}}encryptionKey
 * @property {?HashedId3[]}inlineP2pcdRequest
 * @property {Ieee1609Dot2Certificate}[requestedCertificate]
 * @property {Uint8} [pduFunctionalType]
 * @property {{contributorId:Uint8, extns:EtsiOriginatingHeaderInfoExtension[]}[]}[contributedExtensions]
 * 
 */
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
    /**
     * 
     * @param {DataCursor} dc 
     * @param {*} options 
     * @returns {HeaderInfo}
     */
    static from_oer(dc, options) {
        return super.from_oer(dc, options);
    }
}
/**
 * @property {SignedDataPayload} payload
 * @property {HeaderInfo}headerInfo
 */
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
    /**
     * @param {DataCursor} dc 
     * @returns {ToBeSignedData}
     */
    static from_oer(dc) {
        return super.from_oer(dc, { keep_buffer: true });
    }
}
    /**
     * @property {HashAlgorithmValue} hashId
     * @property {ToBeSignedData} tbsData
     * @property {SignerIdentifier} signer
     * @property {Signature} signature
     */
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
    /**
     * @param {DataCursor} dc 
     * @returns {SignedData}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }

    /**
     * @async
     * @returns {Promise<ArrayBuffer>}
     */
    async tbsHash() {
        return ws.subtle.digest(this.hashId.algorithm, this.tbsData.oer);
    }

    /**
     * 
     * @param {(Ieee1609Dot2Certificate|SignerIdentifier)} signer 
     * @returns {Promise<boolean>}
     */
    async verify(signer) {
        if (signer === undefined) {
            if (Array.isArray(this.signer.certificate) && this.signer.certificate.length > 0)
                signer = this.signer.certificate[0];
            if (signer === undefined)
                return false;
        }
        let tbsHash = await this.tbsHash();
        if (tbsHash) {
//            console.log("TBS Hash: " + inspect(tbsHash, {
//                depth: null, customInspect: true, maxArrayLength: null, showHidden: false
//            }));
            let signer_hash = await signer.hash();

//            console.log("Signer Hash: " + inspect(signer_hash, {
//                depth: null, customInspect: true, maxArrayLength: null, showHidden: false
//            }));
            let d = new Uint8Array(tbsHash.length + signer_hash.length);
            d.set(tbsHash);
            d.set(signer.hash, tbsHash.length);

            let vk = await signer.verificationKey();
            return await wc.subtle.verify( {name:'ECDSA', hash:this.hashId.algorithm},
                              vk, this.signature.ieee_p1363, d);
        }
    }
}
/**
 * @property {HashedId8} [pskRecipInfo]
 * @property {{recipientId:HashedId8,encKey:SymmetricCiphertext}}[symmRecipInfo]
 * @property {PKRecipientInfo} [certRecipInfo]
 * @property {PKRecipientInfo} [signedDataRecipInfo]
 * @property {PKRecipientInfo}[rekRecipInfo]
 */
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
    /**
     * @param {DataCursor} dc 
     * @returns {RecipientInfo}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

/**
 * @property {RecipientInfo[]}recipients
 * @property {SymmetricCiphertext}ciphertext
 */
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
    /**
     * @param {DataCursor} dc 
     * @returns {EncryptedData}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

/**
 * @property {Opaque} unsecuredData
 * @property {SignedData} signedData
 * @property {EncryptedData} encryptedData
 * @property {OctetString} signedCertificateRequest
 */
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
        type: Opaque
    }, {
        extention: true
    }, {
        name: "signedX509CertificateRequest",
        type: Opaque
    }
])
{
    /**
     * @param {DataCursor} dc 
     * @returns {Ieee1609Dot2Content}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }
}

/**
 * @property {Uint8} protocolVersion
 * @property {Ieee1609Dot2Content} content
 */
class Ieee1609Dot2Data extends Sequence([
    {
        name: "protocolVersion",
        type: Uint8
    }, {
        name: "content",
        type: Ieee1609Dot2Content
    }
]) {
    /**
     * @param {DataCursor} dc 
     * @returns {Ieee1609Dot2Data}
     */
    static from_oer(dc) {
        return super.from_oer(dc);
    }

    /**
     * @async
     * @param {DataCursor} signer 
     * @returns {Promise<boolean>}
     */
    async verify(signer) {
        if (this.content && this.content.signedData) {
            return this.content.signedData.verify(signer);
        }
        return Promise.resolve(true);
    }
}

SignedDataPayload_Fields[0].type = Ieee1609Dot2Data;

export {
    CrlSeries, HashAlgorithm, Opaque, Time32, Time64, TwoDLocation, ThreeDLocation, HashedId8, HashedId3, CertificateId, SubjectAssurance,
    LaId, LinkageSeed, GeographicRegion, ValidityPeriod, PsidGroupPermissions, Psid, PsidSsp, IValue,
    EccP256CurvePoint, EccP384CurvePoint, 
    PublicEncryptionKey, PublicVerificationKey, Signature, IssuerIdentifier, SignerIdentifier,
    ToBeSignedCertificate, CertificateType,
    Ieee1609Dot2Certificate, Ieee1609Dot2Data
};
