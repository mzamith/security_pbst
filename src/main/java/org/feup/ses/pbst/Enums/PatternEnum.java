package org.feup.ses.pbst.Enums;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.feup.ses.pbst.Interfaces.Enumerator;

public enum PatternEnum implements Enumerator {

    SPOOFING_AL(0, "S_AL", "Account Lockout"),
    INFORMATION_DISCLOSURE_AS(1, "ID_AS", "Anonymity Set"),
    SPOOFING_AB(2, "S_AB", "Assertion Builder"),
    REPUDIATION_AI(3, "R_AI", "Audit Interceptor"),
    SPOOFING_AE(4, "S_AE", "Authentication Enforcer"),
    INFORMATION_DISCLOSURE_AE(5, "ID_AE", "Authorization Enforcer"),
    //	INFORMATION_DISCLOSURE_BR(6, "ID_BR", "Batched Routing"),
    SPOOFING_BA(7, "S_BA", "Brokered Authentication"),
    //	INFORMATION_DISCLOSURE_C(8, "ID_C", "Chaining"),
    TAMPERING_CS(9, "T_CS", "Checkpointed System"),
    //	TAMPERING_CJ(10, "T_CJ", "Chroot Jail"),
    INFORMATION_DISCLOSURE_CDS(11, "ID_CDS", "Client Data Storage"),
    //	INFORMATION_DISCLOSURE_CMS(12, "ID_CMS", "Container Managed Security"),
    //	TAMPERING_CDP(13, "T_CDP", "Content Dependent Processing"),
    //	INFORMATION_DISCLOSURE_CLP(14, "ID_CLP", "Constant Lenght Padding"),
    //	ELEVATION_OF_PRIVILEGE_C(15, "IOP_C", "Compartmentalization"),
    ELEVATION_OF_PRIVILEGE_COF(16, "IOP_COF", "Controlled Object Factory"),
    ELEVATION_OF_PRIVILEGE_CPC(17, "IOP_CPC", "Controlled Process Creator"),
    //	ELEVATION_OF_PRIVILEGE_CVAS(18, "IOP_CVAP", "Controlled Virtual Address Space"),
    //	INFORMATION_DISCLOSURE_CT(19, "ID_CT", "Cover Traffic"),
    SPOOFING_CT(20, "S_CT", "Credential Tokenizer"),
    MULTI_PURPOSE_DZ(21, "MP_DZ", "Demilitarized Zone"),
    INFORMATION_DISCLOSURE_DS(22, "ID_DS", "Directed Session"),
    //	ELEVATION_OF_PRIVILEGE_DR(23, "IOP_DR", "Distributed Responsibility"),
    INFORMATION_DISCLOSURE_DSM(24, "ID_DSM", "Dynamic Service Management"),
    //	TAMPERING_EDC(25, "T_EDC", "Error Detection And Correction"),
    INFORMATION_DISCLOSURE_ES(26, "ID_ES", "Encrypted Storage"),
    INFORMATION_DISCLOSURE_EXS(27, "ID_EXS", "Exception Shielding"),
    //	ELEVATION_OF_PRIVILEGE_ED(28, "IOP_ED", "Execution Domain"),
    //	MULTI_PURPOSE_FD(29, "MP_FD", "Front Door"),
    INFORMATION_DISCLOSURE_FAWE(30, "ID_FAWE", "Full Access With Errors"),
    MULTI_PURPOSE_IO(31, "MP_IO", "Information Obscurity"),
    INFORMATION_DISCLOSURE_IRP(32, "ID_IRP", "Integration Reverse Proxy"),
    TAMPERING_IV(33, "T_IV", "Intercepting Validator"),
    SPOOFING_IWA(34, "S_IWA", "Interception Web Agent"),
    //	INFORMATION_DISCLOSURE_LE(35, "ID_LE", "Layered Encryption"),
    //	INFORMATION_DISCLOSURE_LA(36, "ID_LA", "Limited Access"),
    //	INFORMATION_DISCLOSURE_LP(37, "ID_LP", "Link Padding"),
    TAMPERING_MI(38, "T_MI", "Message Inspector"),
    TAMPERING_MIG(39, "T_MIG", "Message Interceptor Gateway"),
    SPOOFING_MRD(40, "S_MRD", "Message Replay Detection"),
    //	INFORMATION_DISCLOSURE_MR(41, "ID_MR", "Morphed Representation"),
    MULTI_PURPOSE_MS(42, "MP_MS", "Multilevel Security"),
    SPOOFING_NAB(43, "S_NAB", "Network Address Blacklist"),
    INFORMATION_DISCLOSURE_OTO(44, "ID_OTO", "Obfuscated Transfer Object"),
    //	INFORMATION_DISCLOSURE_OT(45, "ID_OT", "Oblivious Transfer"),
    //	INFORMATION_DISCLOSURE_PFF(46, "ID_PFF", "Packet Filter Firewall"),
    //	SPOOFING_PS(47, "S_PS", "Password Synchronizer"),
    INFORMATION_DISCLOSURE_PD(48, "ID_PD", "Policy Delegate"),
    //	MULTI_PURPOSE_PEP(49, "MP_PEP", "Policy Enforcement Point"),
    //	MULTI_PURPOSE_PRP(50, "MP_PRP", "Protection Reverse Proxy"),
    INFORMATION_DISCLOSURE_PBF(51, "ID_PBF", "Proxy Based Firewall"),
    INFORMATION_DISCLOSURE_PI(52, "ID_PI", "Pseudonymous Identity"),
    //	INFORMATION_DISCLOSURE_RE(53, "ID_RE", "Random Exit"),
    //	INFORMATION_DISCLOSURE_RW(54, "ID_RW", "Random Wait"),
    //	INFORMATION_DISCLOSURE_RM(55, "ID_RM", "Reference Monitor"),
    //	MULTI_PURPOSE_RS(56, "MP_RS", "Replicated System"),
    INFORMATION_DISCLOSURE_RBAC(57, "ID_RBAC", "Role Based Access Control"),
    //	TAMPERING_SDS(58, "T_SDS", "Safe Data Structure"),
    //	DOS_S(59, "DOS_S", "Safety"),
    INFORMATION_DISCLOSURE_SCOM(60, "ID_SCOM", "Secure Communication"),
    REPUDIATION_SL(61, "R_SL", "Secure Logger"),
    TAMPERING_SMR(62, "T_SMR", "Secure Message Router"),
    MULTI_PURPOSE_SSF(63, "MP_SSF", "Secure Service Facade"),
    MULTI_PURPOSE_SSP(64, "MP_SSP", "Secure Service Proxy"),
    INFORMATION_DISCLOSURE_SSO(65, "ID_SSO", "Secure Session Object"),
    //	ELEVATION_OF_PRIVILEGE_SRP(66, "IOP_SRP", "Secure Resource Pooling"),
    INFORMATION_DISCLOSURE_SA(67, "ID_SA", "Security Association"),
    INFORMATION_DISCLOSURE_SC(68, "ID_SC", "Security Context"),
    //	INFORMATION_DISCLOSURE_SS(69, "ID_SS", "Security Session"),
    MULTI_PURPOSE_SS(70, "MP_SS", "Server Sandbox"),
    MULTI_PURPOSE_SAP(71, "MP_SAP", "Single Access Point"),
    //	SPOOFING_SSO(72, "S_SSO", "Single Sign On"),
    //	SPOOFING_SSOD(73, "S_SSOD", "Single Sign On Delegator"),
    //	MULTI_PURPOSE_STF(74, "MP_STF", "Single Threaded Facade"),
    DOS_SP(75, "DOS_SP", "Small Processes"),
    //	MULTI_PURPOSE_S(76, "MP_S", "Standby"),
    //	INFORMATION_DISCLOSURE_SF(77, "ID_SF", "Stateful Firewall"),
    //	INFORMATION_DISCLOSURE_SD(78, "ID_SD", "Subject Descriptor"),
    //	MULTI_PURPOSE_TS(79, "MP_TS", "Tandem System"),
    //	TAMPERING_TP(80, "T_TP", "Trust Partitioning"),
    MULTI_PURPOSE_TP(81, "MP_TP", "Trusted Proxy"), //	TAMPERING_ULFEWR(82, "T_ULFEWR", "Unique Location For Each Write Request")
    ;

    public static final int SPOOFING_AL_VALUE = 0;
    public static final int INFORMATION_DISCLOSURE_AS_VALUE = 1;
    public static final int SPOOFING_AB_VALUE = 2;
    public static final int REPUDIATION_AI_VALUE = 3;
    public static final int SPOOFING_AE_VALUE = 4;
    public static final int INFORMATION_DISCLOSURE_AE_VALUE = 5;
    public static final int INFORMATION_DISCLOSURE_BR_VALUE = 6;
    public static final int SPOOFING_BA_VALUE = 7;
    public static final int INFORMATION_DISCLOSURE_C_VALUE = 8;
    public static final int TAMPERING_CS_VALUE = 9;
    public static final int TAMPERING_CJ_VALUE = 10;
    public static final int INFORMATION_DISCLOSURE_CDS_VALUE = 11;
    public static final int INFORMATION_DISCLOSURE_CMS_VALUE = 12;
    public static final int TAMPERING_CDP_VALUE = 13;
    public static final int INFORMATION_DISCLOSURE_CLP_VALUE = 14;
    public static final int ELEVATION_OF_PRIVILEGE_C_VALUE = 15;
    public static final int ELEVATION_OF_PRIVILEGE_COF_VALUE = 16;
    public static final int ELEVATION_OF_PRIVILEGE_CPC_VALUE = 17;
    public static final int ELEVATION_OF_PRIVILEGE_CVAS_VALUE = 18;
    public static final int INFORMATION_DISCLOSURE_CT_VALUE = 19;
    public static final int SPOOFING_CT_VALUE = 20;
    public static final int MULTI_PURPOSE_DZ_VALUE = 21;
    public static final int INFORMATION_DISCLOSURE_DS_VALUE = 22;
    public static final int ELEVATION_OF_PRIVILEGE_DR_VALUE = 23;
    public static final int INFORMATION_DISCLOSURE_DSM_VALUE = 24;
    public static final int TAMPERING_EDC_VALUE = 25;
    public static final int INFORMATION_DISCLOSURE_ES_VALUE = 26;
    public static final int INFORMATION_DISCLOSURE_EXS_VALUE = 27;
    public static final int ELEVATION_OF_PRIVILEGE_ED_VALUE = 28;
    public static final int MULTI_PURPOSE_FD_VALUE = 29;
    public static final int INFORMATION_DISCLOSURE_FAWE_VALUE = 30;
    public static final int MULTI_PURPOSE_IO_VALUE = 31;
    public static final int INFORMATION_DISCLOSURE_IRP_VALUE = 32;
    public static final int TAMPERING_IV_VALUE = 33;
    public static final int SPOOFING_IWA_VALUE = 34;
    public static final int INFORMATION_DISCLOSURE_LE_VALUE = 35;
    public static final int INFORMATION_DISCLOSURE_LA_VALUE = 36;
    public static final int INFORMATION_DISCLOSURE_LP_VALUE = 37;
    public static final int TAMPERING_MI_VALUE = 38;
    public static final int TAMPERING_MIG_VALUE = 39;
    public static final int SPOOFING_MRD_VALUE = 40;
    public static final int INFORMATION_DISCLOSURE_MR_VALUE = 41;
    public static final int MULTI_PURPOSE_MS_VALUE = 42;
    public static final int SPOOFING_NAB_VALUE = 43;
    public static final int INFORMATION_DISCLOSURE_OTO_VALUE = 44;
    public static final int INFORMATION_DISCLOSURE_OT_VALUE = 45;
    public static final int INFORMATION_DISCLOSURE_PFF_VALUE = 46;
    public static final int SPOOFING_PS_VALUE = 47;
    public static final int INFORMATION_DISCLOSURE_PD_VALUE = 48;
    public static final int MULTI_PURPOSE_PEP_VALUE = 49;
    public static final int MULTI_PURPOSE_PRP_VALUE = 50;
    public static final int INFORMATION_DISCLOSURE_PBF_VALUE = 51;
    public static final int INFORMATION_DISCLOSURE_PI_VALUE = 52;
    public static final int INFORMATION_DISCLOSURE_RE_VALUE = 53;
    public static final int INFORMATION_DISCLOSURE_RW_VALUE = 54;
    public static final int INFORMATION_DISCLOSURE_RM_VALUE = 55;
    public static final int MULTI_PURPOSE_RS_VALUE = 56;
    public static final int INFORMATION_DISCLOSURE_RBAC_VALUE = 57;
    public static final int TAMPERING_SDS_VALUE = 58;
    public static final int DOS_S_VALUE = 59;
    public static final int INFORMATION_DISCLOSURE_SCOM_VALUE = 60;
    public static final int REPUDIATION_SL_VALUE = 61;
    public static final int TAMPERING_SMR_VALUE = 62;
    public static final int MULTI_PURPOSE_SSF_VALUE = 63;
    public static final int MULTI_PURPOSE_SSP_VALUE = 64;
    public static final int INFORMATION_DISCLOSURE_SSO_VALUE = 65;
    public static final int ELEVATION_OF_PRIVILEGE_SRP_VALUE = 66;
    public static final int INFORMATION_DISCLOSURE_SA_VALUE = 67;
    public static final int INFORMATION_DISCLOSURE_SC_VALUE = 68;
    public static final int INFORMATION_DISCLOSURE_SS_VALUE = 69;
    public static final int MULTI_PURPOSE_SS_VALUE = 70;
    public static final int MULTI_PURPOSE_SAP_VALUE = 71;
    public static final int SPOOFING_SSO_VALUE = 72;
    public static final int SPOOFING_SSOD_VALUE = 73;
    public static final int MULTI_PURPOSE_STF_VALUE = 74;
    public static final int DOS_SP_VALUE = 75;
    public static final int MULTI_PURPOSE_S_VALUE = 76;
    public static final int INFORMATION_DISCLOSURE_SF_VALUE = 77;
    public static final int INFORMATION_DISCLOSURE_SD_VALUE = 78;
    public static final int MULTI_PURPOSE_TS_VALUE = 79;
    public static final int TAMPERING_TP_VALUE = 80;
    public static final int MULTI_PURPOSE_TP_VALUE = 81;
    public static final int TAMPERING_ULFEWR_VALUE = 82;

    private static final PatternEnum[] VALUES_ARRAY
            = new PatternEnum[]{
                SPOOFING_AL,
                INFORMATION_DISCLOSURE_AS,
                SPOOFING_AB,
                REPUDIATION_AI,
                SPOOFING_AE,
                INFORMATION_DISCLOSURE_AE,
                //				INFORMATION_DISCLOSURE_BR,
                SPOOFING_BA,
                //				INFORMATION_DISCLOSURE_C,
                TAMPERING_CS,
                //				TAMPERING_CJ,
                INFORMATION_DISCLOSURE_CDS,
                //				INFORMATION_DISCLOSURE_CMS,
                //				TAMPERING_CDP,
                //				INFORMATION_DISCLOSURE_CLP,
                //				ELEVATION_OF_PRIVILEGE_C,
                ELEVATION_OF_PRIVILEGE_COF,
                ELEVATION_OF_PRIVILEGE_CPC,
                //				ELEVATION_OF_PRIVILEGE_CVAS,
                //				INFORMATION_DISCLOSURE_CT,
                SPOOFING_CT,
                MULTI_PURPOSE_DZ,
                INFORMATION_DISCLOSURE_DS,
                //				ELEVATION_OF_PRIVILEGE_DR,
                INFORMATION_DISCLOSURE_DSM,
                //				TAMPERING_EDC,
                INFORMATION_DISCLOSURE_ES,
                INFORMATION_DISCLOSURE_EXS,
                //				ELEVATION_OF_PRIVILEGE_ED,
                //				MULTI_PURPOSE_FD,
                INFORMATION_DISCLOSURE_FAWE,
                MULTI_PURPOSE_IO,
                INFORMATION_DISCLOSURE_IRP,
                TAMPERING_IV,
                SPOOFING_IWA,
                //				INFORMATION_DISCLOSURE_LE,
                //				INFORMATION_DISCLOSURE_LA,
                //				INFORMATION_DISCLOSURE_LP,
                TAMPERING_MI,
                TAMPERING_MIG,
                SPOOFING_MRD,
                //				INFORMATION_DISCLOSURE_MR,
                MULTI_PURPOSE_MS,
                SPOOFING_NAB,
                INFORMATION_DISCLOSURE_OTO,
                //				INFORMATION_DISCLOSURE_OT,
                //				INFORMATION_DISCLOSURE_PFF,
                //				SPOOFING_PS,
                INFORMATION_DISCLOSURE_PD,
                //				MULTI_PURPOSE_PEP,
                //				MULTI_PURPOSE_PRP,
                INFORMATION_DISCLOSURE_PBF,
                INFORMATION_DISCLOSURE_PI,
                //				INFORMATION_DISCLOSURE_RE,
                //				INFORMATION_DISCLOSURE_RW,
                //				INFORMATION_DISCLOSURE_RM,
                //				MULTI_PURPOSE_RS,
                INFORMATION_DISCLOSURE_RBAC,
                //				TAMPERING_SDS,
                //				DOS_S,
                INFORMATION_DISCLOSURE_SCOM,
                REPUDIATION_SL,
                TAMPERING_SMR,
                MULTI_PURPOSE_SSF,
                MULTI_PURPOSE_SSP,
                INFORMATION_DISCLOSURE_SSO,
                //				ELEVATION_OF_PRIVILEGE_SRP,
                INFORMATION_DISCLOSURE_SA,
                INFORMATION_DISCLOSURE_SC,
                //				INFORMATION_DISCLOSURE_SS,
                MULTI_PURPOSE_SS,
                MULTI_PURPOSE_SAP,
                //				SPOOFING_SSO,
                //				SPOOFING_SSOD,
                //				MULTI_PURPOSE_STF,
                DOS_SP,
                //				MULTI_PURPOSE_S,
                //				INFORMATION_DISCLOSURE_SF,
                //				INFORMATION_DISCLOSURE_SD,
                //				MULTI_PURPOSE_TS,
                //				TAMPERING_TP,
                MULTI_PURPOSE_TP, //				TAMPERING_ULFEWR
            };

    public static PatternEnum get(int value) {
        switch (value) {
            case SPOOFING_AL_VALUE:
                return SPOOFING_AL;
            case INFORMATION_DISCLOSURE_AS_VALUE:
                return INFORMATION_DISCLOSURE_AS;
            case SPOOFING_AB_VALUE:
                return SPOOFING_AB;
            case REPUDIATION_AI_VALUE:
                return REPUDIATION_AI;
            case SPOOFING_AE_VALUE:
                return SPOOFING_AE;
            case INFORMATION_DISCLOSURE_AE_VALUE:
                return INFORMATION_DISCLOSURE_AE;
//			case INFORMATION_DISCLOSURE_BR_VALUE: return INFORMATION_DISCLOSURE_BR;
            case SPOOFING_BA_VALUE:
                return SPOOFING_BA;
//			case INFORMATION_DISCLOSURE_C_VALUE: return INFORMATION_DISCLOSURE_C;
            case TAMPERING_CS_VALUE:
                return TAMPERING_CS;
//			case TAMPERING_CJ_VALUE: return TAMPERING_CJ;
            case INFORMATION_DISCLOSURE_CDS_VALUE:
                return INFORMATION_DISCLOSURE_CDS;
//			case INFORMATION_DISCLOSURE_CMS_VALUE: return INFORMATION_DISCLOSURE_CMS;
//			case TAMPERING_CDP_VALUE: return TAMPERING_CDP;
//			case INFORMATION_DISCLOSURE_CLP_VALUE: return INFORMATION_DISCLOSURE_CLP;
//			case ELEVATION_OF_PRIVILEGE_C_VALUE: return ELEVATION_OF_PRIVILEGE_C;
            case ELEVATION_OF_PRIVILEGE_COF_VALUE:
                return ELEVATION_OF_PRIVILEGE_COF;
            case ELEVATION_OF_PRIVILEGE_CPC_VALUE:
                return ELEVATION_OF_PRIVILEGE_CPC;
//			case ELEVATION_OF_PRIVILEGE_CVAS_VALUE: return ELEVATION_OF_PRIVILEGE_CVAS;
//			case INFORMATION_DISCLOSURE_CT_VALUE: return INFORMATION_DISCLOSURE_CT;
            case SPOOFING_CT_VALUE:
                return SPOOFING_CT;
            case MULTI_PURPOSE_DZ_VALUE:
                return MULTI_PURPOSE_DZ;
            case INFORMATION_DISCLOSURE_DS_VALUE:
                return INFORMATION_DISCLOSURE_DS;
//			case ELEVATION_OF_PRIVILEGE_DR_VALUE: return ELEVATION_OF_PRIVILEGE_DR;
            case INFORMATION_DISCLOSURE_DSM_VALUE:
                return INFORMATION_DISCLOSURE_DSM;
//			case TAMPERING_EDC_VALUE: return TAMPERING_EDC;
            case INFORMATION_DISCLOSURE_ES_VALUE:
                return INFORMATION_DISCLOSURE_ES;
            case INFORMATION_DISCLOSURE_EXS_VALUE:
                return INFORMATION_DISCLOSURE_EXS;
//			case ELEVATION_OF_PRIVILEGE_ED_VALUE: return ELEVATION_OF_PRIVILEGE_ED;
//			case MULTI_PURPOSE_FD_VALUE: return MULTI_PURPOSE_FD;
            case INFORMATION_DISCLOSURE_FAWE_VALUE:
                return INFORMATION_DISCLOSURE_FAWE;
            case MULTI_PURPOSE_IO_VALUE:
                return MULTI_PURPOSE_IO;
            case INFORMATION_DISCLOSURE_IRP_VALUE:
                return INFORMATION_DISCLOSURE_IRP;
            case TAMPERING_IV_VALUE:
                return TAMPERING_IV;
            case SPOOFING_IWA_VALUE:
                return SPOOFING_IWA;
//			case INFORMATION_DISCLOSURE_LE_VALUE: return INFORMATION_DISCLOSURE_LE;
//			case INFORMATION_DISCLOSURE_LA_VALUE: return INFORMATION_DISCLOSURE_LA;
//			case INFORMATION_DISCLOSURE_LP_VALUE: return INFORMATION_DISCLOSURE_LP;
            case TAMPERING_MI_VALUE:
                return TAMPERING_MI;
            case TAMPERING_MIG_VALUE:
                return TAMPERING_MIG;
            case SPOOFING_MRD_VALUE:
                return SPOOFING_MRD;
//			case INFORMATION_DISCLOSURE_MR_VALUE: return INFORMATION_DISCLOSURE_MR;
            case MULTI_PURPOSE_MS_VALUE:
                return MULTI_PURPOSE_MS;
            case SPOOFING_NAB_VALUE:
                return SPOOFING_NAB;
            case INFORMATION_DISCLOSURE_OTO_VALUE:
                return INFORMATION_DISCLOSURE_OTO;
//			case INFORMATION_DISCLOSURE_OT_VALUE: return INFORMATION_DISCLOSURE_OT;
//			case INFORMATION_DISCLOSURE_PFF_VALUE: return INFORMATION_DISCLOSURE_PFF;
//			case SPOOFING_PS_VALUE: return SPOOFING_PS;
            case INFORMATION_DISCLOSURE_PD_VALUE:
                return INFORMATION_DISCLOSURE_PD;
//			case MULTI_PURPOSE_PEP_VALUE: return MULTI_PURPOSE_PEP;
//			case MULTI_PURPOSE_PRP_VALUE: return MULTI_PURPOSE_PRP;
            case INFORMATION_DISCLOSURE_PBF_VALUE:
                return INFORMATION_DISCLOSURE_PBF;
            case INFORMATION_DISCLOSURE_PI_VALUE:
                return INFORMATION_DISCLOSURE_PI;
//			case INFORMATION_DISCLOSURE_RE_VALUE: return INFORMATION_DISCLOSURE_RE;
//			case INFORMATION_DISCLOSURE_RW_VALUE: return INFORMATION_DISCLOSURE_RW;
//			case INFORMATION_DISCLOSURE_RM_VALUE: return INFORMATION_DISCLOSURE_RM;
//			case MULTI_PURPOSE_RS_VALUE: return MULTI_PURPOSE_RS;
            case INFORMATION_DISCLOSURE_RBAC_VALUE:
                return INFORMATION_DISCLOSURE_RBAC;
//			case TAMPERING_SDS_VALUE: return TAMPERING_SDS;
//			case DOS_S_VALUE: return DOS_S;
            case INFORMATION_DISCLOSURE_SCOM_VALUE:
                return INFORMATION_DISCLOSURE_SCOM;
            case REPUDIATION_SL_VALUE:
                return REPUDIATION_SL;
            case TAMPERING_SMR_VALUE:
                return TAMPERING_SMR;
            case MULTI_PURPOSE_SSF_VALUE:
                return MULTI_PURPOSE_SSF;
            case MULTI_PURPOSE_SSP_VALUE:
                return MULTI_PURPOSE_SSP;
            case INFORMATION_DISCLOSURE_SSO_VALUE:
                return INFORMATION_DISCLOSURE_SSO;
//			case ELEVATION_OF_PRIVILEGE_SRP_VALUE: return ELEVATION_OF_PRIVILEGE_SRP;
            case INFORMATION_DISCLOSURE_SA_VALUE:
                return INFORMATION_DISCLOSURE_SA;
            case INFORMATION_DISCLOSURE_SC_VALUE:
                return INFORMATION_DISCLOSURE_SC;
//			case INFORMATION_DISCLOSURE_SS_VALUE: return INFORMATION_DISCLOSURE_SS;
            case MULTI_PURPOSE_SS_VALUE:
                return MULTI_PURPOSE_SS;
            case MULTI_PURPOSE_SAP_VALUE:
                return MULTI_PURPOSE_SAP;
//			case SPOOFING_SSO_VALUE: return SPOOFING_SSO;
//			case SPOOFING_SSOD_VALUE: return SPOOFING_SSOD;
//			case MULTI_PURPOSE_STF_VALUE: return MULTI_PURPOSE_STF;
            case DOS_SP_VALUE:
                return DOS_SP;
//			case MULTI_PURPOSE_S_VALUE: return MULTI_PURPOSE_S;
//			case INFORMATION_DISCLOSURE_SF_VALUE: return INFORMATION_DISCLOSURE_SF;
//			case INFORMATION_DISCLOSURE_SD_VALUE: return INFORMATION_DISCLOSURE_SD;
//			case MULTI_PURPOSE_TS_VALUE: return MULTI_PURPOSE_TS;
//			case TAMPERING_TP_VALUE: return TAMPERING_TP;
            case MULTI_PURPOSE_TP_VALUE:
                return MULTI_PURPOSE_TP;
//			case TAMPERING_ULFEWR_VALUE: return TAMPERING_ULFEWR;

        }
        return null;
    }

    public static final List<PatternEnum> VALUES = Collections.unmodifiableList(Arrays.asList(VALUES_ARRAY));

    public static PatternEnum get(String literal) {
        for (int i = 0; i < VALUES_ARRAY.length; ++i) {
            PatternEnum result = VALUES_ARRAY[i];
            if (result.toString().equals(literal)) {
                return result;
            }
        }
        return null;
    }

    public static PatternEnum getByName(String name) {
        for (int i = 0; i < VALUES_ARRAY.length; ++i) {
            PatternEnum result = VALUES_ARRAY[i];
            if (result.getName().equals(name)) {
                return result;
            }
        }
        return null;
    }

    private final int value;
    private final String name;
    private final String literal;

    private PatternEnum(int value, String name, String literal) {
        this.value = value;
        this.name = name;
        this.literal = literal;
    }

    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    public String getLiteral() {
        return literal;
    }

    @Override
    public String toString() {
        return literal;
    }
}
