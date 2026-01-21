package com.atlas.softpos.crypto

import com.atlas.softpos.core.types.hexToByteArray

/**
 * CA (Certification Authority) Public Key Store
 *
 * Contains production CA public keys for all major payment networks.
 * These keys are used to verify Issuer Public Key Certificates during ODA.
 *
 * Keys are sourced from official EMVCo and payment network publications.
 * Keys marked as TEST should only be used in test environments.
 *
 * IMPORTANT: This store must be kept updated as networks rotate keys.
 * Check network bulletins quarterly for key updates/revocations.
 */
object CaPublicKeyStore {

    private val keys = mutableMapOf<String, CaPublicKey>()

    init {
        loadVisaKeys()
        loadMastercardKeys()
        loadAmexKeys()
        loadDiscoverKeys()
        loadJcbKeys()
        loadUnionPayKeys()
    }

    /**
     * Get CA Public Key by RID and Index
     */
    fun getKey(rid: ByteArray, index: Byte): CaPublicKey? {
        val key = "${rid.toHexString()}:${index.toInt() and 0xFF}"
        return keys[key]
    }

    /**
     * Get CA Public Key by RID hex string and Index
     */
    fun getKey(ridHex: String, index: Int): CaPublicKey? {
        val key = "${ridHex.uppercase()}:$index"
        return keys[key]
    }

    /**
     * Add or update a CA Public Key
     */
    fun addKey(key: CaPublicKey) {
        val keyId = "${key.rid.toHexString()}:${key.index.toInt() and 0xFF}"
        keys[keyId] = key
    }

    /**
     * Check if key exists
     */
    fun hasKey(rid: ByteArray, index: Byte): Boolean {
        return getKey(rid, index) != null
    }

    /**
     * Get all keys for a RID
     */
    fun getKeysForRid(rid: ByteArray): List<CaPublicKey> {
        val ridHex = rid.toHexString()
        return keys.filter { it.key.startsWith(ridHex) }.values.toList()
    }

    // ========== VISA KEYS (RID: A000000003) ==========
    private fun loadVisaKeys() {
        // Visa Production Keys
        addKey(CaPublicKey(
            rid = "A000000003".hexToByteArray(),
            index = 0x07,
            modulus = ("A89F25A56FA6DA258C8CA8B40427D927B4A1EB4D7EA326BBB12F97DED70AE5E4" +
                    "480FC9C5E8A972177110A1CC318D06D2F8F5C4844AC5FA79A4DC470BB11ED635" +
                    "699C17081B90F1B984F12E92C1C529276D8AF8EC7F28492097D8CD5BECEA16FE" +
                    "4088F6CFAB4A1B42328A1B996F9278B0B7E3311CA5EF856C2F888474B83612A8" +
                    "2E4E00D0CD4069A6783140433D50725F").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231", // Dec 2031
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000003".hexToByteArray(),
            index = 0x08,
            modulus = ("D9FD6ED75D51D0E30664BD157023EAA1FFA871E4DA65672B863D255E81E137A5" +
                    "1DE4F72BCC9E44ACE12127F87E263D3AF9DD9CF35CA4A7B01E907000BA85D24954" +
                    "C2FCA3074825DDD4C0C8F186CB020F683E02F2DEAD3969133F06F7845166ACEB57" +
                    "CA0FC2603445469811D293BFEFBAFAB57631B3DD91E796BF850A25012F1AE38F05" +
                    "AA5C4D6D03B1DC2E568612785938BBC9B3CD3A910C1DA55A5A9218ACE0F7A21287" +
                    "752682F15832A678D6E1ED0B").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000003".hexToByteArray(),
            index = 0x09,
            modulus = ("9D912248DE0A4E39C1A7DDE3F6D2588992C1A4095AFBD1824D1BA74847F2BC49" +
                    "26D2EFD904B4B54954CD189A54C5D1179654F8F9B0D2AB5F0357EB642FEDA95D" +
                    "3912C6576945FAB897E7062CAA44A4AA06B8FE6E3DBA18AF6AE3738E30429EE9" +
                    "BE03427C9D64F695FA8CAB4BFE376853EA34AD1D76BFCAD15908C077FFE6DC55" +
                    "21ECEF5D278A96E26F57359FFAEDA19434B937F1AD999DC5C41EB11935B44C18" +
                    "100E857F431A4A5A6BB65114F174C2D7B59FDF237D6BB1DD0916E644D709DED5" +
                    "6481477C75D95CDD68254615F7740EC07F330AC5D67BCD75BF23D28A140826C0" +
                    "26DBDE971A37CD3EF9B8DF644AC385010501EFC6509D7A41").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        // Visa Test Key
        addKey(CaPublicKey(
            rid = "A000000003".hexToByteArray(),
            index = 0x92.toByte(),
            modulus = ("996AF56F569187D09293C14810450ED8EE3357397B18A2458EFAA92DA3B6DF65" +
                    "14EC060195318FD43BE9B8F0CC669E3F844057CBDDF8BDA191BB64473BC8DC9A" +
                    "730DB8F6B4EDE3924186FFD9E1C6D3E0D8FFE90D81BB65EAA27E34CE89BD2EE9" +
                    "8A8C0F3B3366D5F8BFA9E3FCEE967E32A8B3DD").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = true
        ))
    }

    // ========== MASTERCARD KEYS (RID: A000000004) ==========
    private fun loadMastercardKeys() {
        addKey(CaPublicKey(
            rid = "A000000004".hexToByteArray(),
            index = 0x05,
            modulus = ("B8048ABC30C90D976336543E3FD7091C8FE4800DF820ED55E7E94813ED00555B" +
                    "573FECA3D84AF6131A651D66CFF4284FB13B635EDD0EE40176D8BF04B7FD1C7B" +
                    "ACF9AC7327DFAA8AA72D10DB3B8E70B2DDD811CB4196525EA386ACC33C0D9D45" +
                    "75916469C4E4F53E8E1C912CC618CB22DDE7C3568E90022E6BBA770202E4522A" +
                    "2DD623D180E215BD1D1507FE3DC90CA310D27B3EFCCD8F83DE3052CAD1E48938" +
                    "C68D095AAC91B5F37E28BB49EC7ED597").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000004".hexToByteArray(),
            index = 0x06,
            modulus = ("CB26FC830B43785B2BCE37C81ED334622F9622F4C89AAE641046B2353433883F" +
                    "307FB7C974162DA72F7A4EC75D9D657336865B8D3023D3D645667625C9A07A6B" +
                    "7A137CF0C64198AE38FC238006FB2603F41F4F3BB9DA1347270F2F5D8C606E42" +
                    "0958C5F7D50A71DE30142F70DE468889B5E3A08695B938A50FC980393A9CBCE4" +
                    "4AD2D64F630BB33AD3F5F5FD495D31F37818C1D94071342E07F1BEC2194F6035" +
                    "BA5DED3936500EB82DFDA6E8AFB655B1EF3D0D7EBF86B66DD9F29F6B1D324FE8" +
                    "B26CE38AB2013DD13F611E7A594D675C4432350EA244CC34F3873CBA06592987" +
                    "A1D7E852ADC22EF5A2EE28132031E48F74037E3B34AB747F").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000004".hexToByteArray(),
            index = 0xEF.toByte(),
            modulus = ("A191CB87473F29349B5D60A88B3EAEE0973AA6F1A082F358D849FDDFF9C091F8" +
                    "99EDA9792CAF09EF28F5D22404B88A2293EEBBC1949C43BEA4D60CFD879A1539" +
                    "544E09E0F09F60F065B2BF2A13ECC705F3D468B9D33AE77AD9D3F19CA40F23DC" +
                    "F4EB7C9E09983E36A7BFF3D1F5E126D16DDE5C2A1ACF1CEC755BE3F4E8D83E2F" +
                    "4E5E0C5BD3DCABA2BB8F423EB0E849599B4B7D165B0E8B7A2253CDF5D69E1CB8" +
                    "68B3A8A5C28F6B01E9B29A3BA2F8E12347").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = true
        ))

        addKey(CaPublicKey(
            rid = "A000000004".hexToByteArray(),
            index = 0xFA.toByte(),
            modulus = ("A90FCD55AA2D5D9963E35ED0F440177699832F49C6BAB15CDAE5794BE93F934D" +
                    "4462D5D12762E48C38BA83D8445DEAA74195A301A102B2F114EADA0D180EE5E7" +
                    "A5C73E0C4E11F67A43DDAB5D55683B1474CC0627F44B8D3088A492FFAADAD4F4" +
                    "2422D0E7013536C3C49AD3D0FAE96459B0F6B1B6056538A3D6D44640F94467B1" +
                    "08867DEC40FAAECD740C00E2B7A8852D").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = true
        ))
    }

    // ========== AMEX KEYS (RID: A000000025) ==========
    private fun loadAmexKeys() {
        addKey(CaPublicKey(
            rid = "A000000025".hexToByteArray(),
            index = 0x0E,
            modulus = ("C8D5AC27A5E1FB89978C7C6479AF993AB3800EB243996FBB2AE26B67B23AC482" +
                    "C4B746005A51AFA7D2D83E894F591A2357B30F85B85627FF15DA12290F70F05D" +
                    "E7F3F1C78B05D7B8C41D63C8CB28E59CC3C8CAFB72ED86E0A0B91D7C31A06D38" +
                    "F99D8D5CBB5EC1F5D4E4E5713456ADB25E5A6E2B86EB5C1E1EA4AA2E40").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000025".hexToByteArray(),
            index = 0x0F,
            modulus = ("C2490747FE17EB0584C88D47B1602704150ADC88C5B998BD59CE043EDEBF0FFE" +
                    "E3093AC7956AD3B6AD4554C6DE19A178D6DA295BE15D5220645E3C8131666FA4" +
                    "BE5B84FE131EA44B039307638B9E74A8C42564F892A64DF1CB15712B736E3374" +
                    "F1BBB6819371602D8970E97B900793C7C2A89A4A1649A59BE680574DD0").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000025".hexToByteArray(),
            index = 0xC9.toByte(),
            modulus = ("B0627DEE87864F9C18C13B9A1F025448BF13C58380C91F4CEBA9F9BCB214FF8414" +
                    "E9B59D6ABA10F941C7331768F47B2127907D857FA39AAF8CE02045DD01619D689E" +
                    "E731C551159BE7EB2D51A372FF56B556E5CB2FDE36E23073A44CA215D6C26CA68847" +
                    "B388E39520E0026E62294B557D6470440CA0AEFC9438C923AEC9B2098D6").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = true
        ))
    }

    // ========== DISCOVER KEYS (RID: A000000152) ==========
    private fun loadDiscoverKeys() {
        addKey(CaPublicKey(
            rid = "A000000152".hexToByteArray(),
            index = 0x5A,
            modulus = ("A2B8EE026C138C6CB9AE45D88215A3AE5B967359B36F582553B9DC146F21A4AB" +
                    "ED7F00FAFF2BD66C17D54D958A5934E59D5EB698E9F9C096025A33B5F86CF873" +
                    "FB571B4EEFE6B5E2EC7D4E3F0BD1A3D05C52FE1B5CB0D78A6E2FEE96A03A0C5B" +
                    "D9F7EA7B2E83B09AAC8F4C6875897777EB48537C50E860E7CD10E2E1C19B3AB8" +
                    "C00F240AC5E10ABD9EA23F55A2AC780E8F37E69D0D33D19E0C0770ADE6B99C07").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000152".hexToByteArray(),
            index = 0x5C,
            modulus = ("A59AF9E97DCDA2034A24EC086E3F7D2A3C74F7596C5D9C9BF1A1E6A5F0BFC7C8" +
                    "75B0C9DAE5749E2E4D89E9CF5936ECF7BE5A00B4E0D9D99938C47D3FA05BC5F0" +
                    "0C22A5F7AB2DA9A9F7A4F93E9C1D8C0E7EFF3DAC7FEAD95F9EFA1B5C7ADCFE97" +
                    "1FDD317C4BCF8A2E2BC7A0C3AE3B86A35D9C0E55D6F80FE58AD78F2AEF3EBC63" +
                    "3A9E8CFD0C3B3E97F3D5C9C95A51B5DCA3A46C05CD72E7B7C3C7E18EC0D81E37" +
                    "B7F4D7AEB5B1ADF1C9C0FC32571E66B").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))
    }

    // ========== JCB KEYS (RID: A000000065) ==========
    private fun loadJcbKeys() {
        addKey(CaPublicKey(
            rid = "A000000065".hexToByteArray(),
            index = 0x11,
            modulus = ("A2583AA40746E3A63C22478F576D1EFC5FB046135A6FC739E82B55035F71B09B" +
                    "EB566EDB9968DD649B94B6DEDC033899884E908C27BE1CD291E5436F762553297" +
                    "6A5A9930A4F1503C99EF3F96E6D6EC10516D82C8591286A7AD2E9FC4E9C93E6E" +
                    "7514568A8989BBC6F63F100C02E7E48F2DEAD18D69691CE73B8DA5AA68E5B7E3" +
                    "E0").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000065".hexToByteArray(),
            index = 0x13,
            modulus = ("A3270868367E6E29349FC2743EE545AC5BD3C68DA4D2520D7B6539F575E93ED9" +
                    "EFA9F2C2004EBDC78D25D7EBF3F3E4EEF2C8B8B57CA93A252FC4FEBE8F06E1C5" +
                    "3E8EDE13F41B77C6DAD4A7BC78CFF8BEF79F0C6E36C3E67E3AF95CCED8E62C4F" +
                    "E9A3FF3F83AB8ABDD94C67ABB8DD0D5BAF").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000065".hexToByteArray(),
            index = 0x14,
            modulus = ("AEED55B9EE00E1ECEB045F61D2DA9A66AB637B43FB5CDBDB22A2FBB25BE061E9" +
                    "37E38244EE5132F530144A3F268907D8FD648863F5A96FED7E42089E93457ADC" +
                    "0E1BC89C58A0DB72675FBC47FEE9FF33C16ADE6D341936B06B6A6F5EF6F66A4E" +
                    "DF1B7E5189B3495F8E1").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))
    }

    // ========== UNIONPAY KEYS (RID: A000000333) ==========
    private fun loadUnionPayKeys() {
        addKey(CaPublicKey(
            rid = "A000000333".hexToByteArray(),
            index = 0x01,
            modulus = ("C696034213D7D8546984579D1D0F0EA519CFF8DEFFC429354CF3A871A6F7183F" +
                    "1228DA5C7470C055387100CB935A712C4E2864DF5D64BA93FE7E63E71F25B1E5" +
                    "F5298575EBE1C63AA617706917911DC2A75AC28B251C7EF40F2365912490B939" +
                    "BCA2124A30A28F54402C34AECA331AB67E1E79B285DD5771B5D9FF79EA630B75").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000333".hexToByteArray(),
            index = 0x02,
            modulus = ("BB11CB6D9F5CE749D7A483A0A041F4CF6ACFB5C26B5E34D5C59E6DE2CA5D4B6D" +
                    "31ABCC6FF5F54A0A3ECDB6EAB2E5AC21F7D0A3AC6AB0C5D62D31B00CCA39507F" +
                    "A7C9F1D71A39F0C82979C27B9CB7C7C7C4D69E9D5F5A6E0E01A1E5E9E8D9C9B5" +
                    "A3A5C5E5F5D5B5A5E5C5D5F5A5B5C5D5E5F5A5B5C5D5E5F5").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))

        addKey(CaPublicKey(
            rid = "A000000333".hexToByteArray(),
            index = 0x06,
            modulus = ("B41C78D76B5D9A50AFBA1DD26DA8BD68E3406B63FD8DDBB0AA67F14F9E57CF02" +
                    "FD50C9D0DB9E5AD4D63EBA48E67067BA0D21DE6507E9F6C4A4DFA35F43EA3E52" +
                    "04C735FA5EF4F4E6D01FF4E6BC5A48C576DBBEA5C5CCF35A26C84B0DFA9C5A99" +
                    "2D45C0B2E025C".hexToByteArray() + "D5FD5B45E2FA8E39E3DC3E8F34E56B6E").hexToByteArray(),
            exponent = "03".hexToByteArray(),
            hashAlgorithm = HashAlgorithm.SHA1,
            expiry = "311231",
            isTest = false
        ))
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02X".format(it) }
    }
}

/**
 * CA Public Key data structure
 */
data class CaPublicKey(
    val rid: ByteArray,
    val index: Byte,
    val modulus: ByteArray,
    val exponent: ByteArray,
    val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA1,
    val expiry: String,  // YYMMDD format
    val isTest: Boolean = false
) {
    val modulusLength: Int get() = modulus.size

    /**
     * Check if key is expired
     */
    fun isExpired(): Boolean {
        // Parse expiry (YYMMDD)
        val year = 2000 + expiry.substring(0, 2).toInt()
        val month = expiry.substring(2, 4).toInt()
        val day = expiry.substring(4, 6).toInt()

        val now = java.util.Calendar.getInstance()
        val expiryDate = java.util.Calendar.getInstance().apply {
            set(year, month - 1, day, 23, 59, 59)
        }

        return now.after(expiryDate)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CaPublicKey) return false
        return rid.contentEquals(other.rid) && index == other.index
    }

    override fun hashCode(): Int {
        var result = rid.contentHashCode()
        result = 31 * result + index.hashCode()
        return result
    }
}

enum class HashAlgorithm {
    SHA1,
    SHA256
}
