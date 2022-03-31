import { iSequenceOf, Uint16, Uint8 } from "asnjs";
import { DataCursor, iEnumerated, iChoice, iOctetString,IA5String, iSequence, iInteger} from "asnjs";

declare module "Ieee1609Dot2js" {
  type HashAlgorithm = "SHA-256" | "SHA-384";
  export class Opaque extends iOctetString{
  }
  export class Time32 extends Date {
  }
  export class Time64 extends Date {
  }
  export class HashedId8 extends iOctetString{
  }
  export class HashedId3 extends iOctetString{
  }
  export class IssuerIdentifier extends iChoice {
    sha256AndDigest?:HashedId8;
    self?:HashAlgorithm;
    sha384AndDigest?:HashedId8;
  }
  export class Duration extends iChoice {
    microseconds?: Uint16;
    milliseconds?: Uint16;
    seconds?: Uint16;
    minutes?: Uint16;
    hours?: Uint16;
    sixtyHours?: Uint16;
    years?: Uint16;
  }
  export class ValidityPeriod extends iSequence {
    start:Time32;
    duration:Duration
  }
  export class CertificateId extends iChoice{
    linkageData?:any;
    name?:string;
    binaryId?:Opaque;
  }
  export class Latitude extends iInteger{}
  export class Longitude extends iInteger{}

  export class TwoDLocation extends iSequence{
    latitude: Latitude
    longitude: Longitude
  }

  export class ThreeDLocation extends iSequence{
    latitude: Latitude
    name: Longitude
    elevation:number
  }

  export class SubjectAssurance {
    static from_oer(dc: DataCursor): SubjectAssurance;
  }
  export class GeographicRegion {
    circularRegion?:{
      center:TwoDLocation;
      radius:Uint16;
    };
    rectangularRegion?:{
      northWest:TwoDLocation;
      southEast:TwoDLocation;
    }[];
    polygonalRegion?:TwoDLocation[];
    identifiedRegion?:{
      countryOnly?:Uint16;
      countryAndRegions?: {
        countryOnly: Uint16;
        regions:Uint8[];
      }
      countryAndSubregions?: {
        countryOnly: Uint16;
        regionAndSubregions:{
          region: Uint8;
          subregions:Uint16[];
        }[];
      }
    }[];
    static from_oer(dc: DataCursor): GeographicRegion;
  }
  export class ServiceSpecificPermissions {
    opaque?: Opaque;
    bitmapSsp?: Opaque;
  }
  type EeType = "none"|"app"|"enrol"|"all";
  export class PsidGroupPermissions {
    subjectPermissions: {
      explicit?:{
        psid:Psid;
        sspRange?:{
          opaque?:iOctetString[];
          all?:boolean;
          bitmapSspRange?:{
            sspValue:Opaque;
            sspBitmask:Opaque;
          }
        }
      }[];
      all?:boolean;
    };
    minChainLength: iInteger;
    chainLengthRange: iInteger;
    eeType: EeType;
    static from_oer(dc: DataCursor): PsidGroupPermissions;
  }
  export class Psid extends iInteger {}
  export class PsidSsp extends iSequence {
    psid: Psid;
    ssp: ServiceSpecificPermissions;
  }
  
  type EccPointType = 0 | 2 | 3 | 4;

  export class EccP256CurvePoint {
    type: EccPointType;
    get x(): iOctetString;
    get y(): iOctetString;
    to_der(algorithm:string): Uint8Array;
  }
  export class EccP384CurvePoint {
    type: EccPointType;
    get x(): iOctetString;
    get y(): iOctetString;
    to_der(algorithm:string): Uint8Array;
  }
  type SymmetricEncryptionKey = 1;

  export class PublicEncryptionKey {
    supportedSymmAlg: SymmetricEncryptionKey;
    publicKey: {
      eciesNistP256?: EccP256CurvePoint;
      eciesBrainpoolP256r1?:EccP256CurvePoint
    };
    static from_oer(dc: DataCursor): PublicEncryptionKey;
  }
  export class PublicVerificationKey {
    ecdsaNistP256?: EccP256CurvePoint;
    ecdsaBrainpoolP256r1?:EccP256CurvePoint;
    ecdsaBrainpoolP384r1?:EccP384CurvePoint;
    hashAlgorithm(): string;
    verificationAlgorithm(): string;
    to_der(): Uint8Array;
    static from_oer(dc: DataCursor): PublicVerificationKey;
  }
  export class EcdsaP256Signature {
    rSig: EccP256CurvePoint;
    sSig: iOctetString;
    get ieee_p1363():Uint8Array;
  }
  export class EcdsaP384Signature {
    rSig: EccP384CurvePoint;
    sSig: iOctetString;
    get ieee_p1363():Uint8Array;
  }
  export class Signature {
    ecdsaNistP256Signature?: EcdsaP256Signature;
    ecdsaBrainpoolP256r1Signature?:EcdsaP256Signature;
    ecdsaBrainpoolP384r1Signature?:EcdsaP384Signature; 

    static from_oer(dc: DataCursor): Signature;
    hashAlgorithm(): string;
    verificationAlgorithm(): string;
    get ieee_p1363(): Uint8Array;
  }
  export class VerificationKeyIndicator {
    verificationKey?: PublicVerificationKey;
    reconstructionValue?:EccP256CurvePoint;
    hashAlgorithm():string;
  }
  export class ToBeSignedCertificate {
    id: CertificateId;
    cracaId: HashedId3;
    crlSeries: number;
    validityPeriod: ValidityPeriod;
    region?: GeographicRegion;
    assuranceLevel?:SubjectAssurance;
    appPermissions?:PsidSsp[];
    certIssuePermissions?:PsidGroupPermissions[];
    certRequestPermissions?:PsidGroupPermissions[];
    canRequestRollover?:boolean;
    encryptionKey?:PublicEncryptionKey;
    verifyKeyIndicator:VerificationKeyIndicator;
  }
  type CertificateType = 'implicit' | 'explicit';
  export class Ieee1609Dot2Certificate {
    version: number;
    type: CertificateType;
    issuer: IssuerIdentifier;
    toBeSigned:ToBeSignedCertificate;
    signature?:Signature;
    hash(): Promise<Uint8Array>;
    digest(): Promise<Uint8Array>;
    issuer_digest(): Promise<Uint8Array>;
    verificationKey(): Promise<CryptoKey>;
    verificationHashAlgorithm: string;
    verificationAlgorithm: string;
    verify(signer: Ieee1609Dot2Certificate): Promise<boolean>;
    static from_oer(dc: DataCursor): Ieee1609Dot2Certificate;
  }
  export class Ieee1609Dot2Data {
      static from_oer(dc: DataCursor): Ieee1609Dot2Data;
      verify(signer: Ieee1609Dot2Certificate): Promise<boolean>;
  }
}
